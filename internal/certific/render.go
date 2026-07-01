package certific

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// LiveDirName is the subdirectory of the download out-dir that certific
// keeps in lockstep with the certs in acme.json. Gateway Traefik points its
// file provider at <out-dir>/live and relies on directory watching: every
// change certific makes here is an in-place create / replace / remove of a
// file *inside* this directory, which fires an inotify event, so Traefik's
// `--providers.file.watch=true` reloads on its own.
//
// This replaced an earlier `current` symlink that was repointed at a fresh
// versions/<id>/ directory on every rotation. Traefik's fsnotify watch
// resolves the symlink and binds to the *target directory's* inode, so a
// symlink repoint fires no event in the watched directory — freshly-issued
// certs landed on disk but were never served until the gateway Traefik was
// restarted. Writing in place removes that gap by construction.
const LiveDirName = "live"

// stagingDirName is a scratch directory, a sibling of LiveDirName under the
// out-dir, where each new file is written before being renamed into the
// live directory. It sits OUTSIDE the watched live dir so Traefik never
// observes a half-written temp file, and on the same filesystem so the
// rename into live/ is atomic (rename(2) is atomic across directories on
// one mount).
const stagingDirName = ".staging"

// AcmeFile is the on-disk shape of Traefik's acme.json: one top-level
// entry per certificatesResolver, each carrying that resolver's account
// data and the certificates it has issued. We only care about the
// certificates — the account material stays in S3 with the rest of the
// file and is never written to gateway disks.
//
// Field names match Traefik v3's JSON output exactly (PascalCase, with
// "domain"/"certificate"/"key" lowercase inside each entry). Resolver
// names are not enumerated: the top-level map carries whatever names the
// issuer was configured with.
type AcmeFile map[string]AcmeResolver

// AcmeResolver is the per-resolver block inside acme.json. Account is
// retained for forward-compatibility with consumers that want to inspect
// the ACME account (we don't), and ignored by the renderer.
type AcmeResolver struct {
	Account      json.RawMessage   `json:"Account"`
	Certificates []AcmeCertificate `json:"Certificates"`
}

// AcmeCertificate is a single issued certificate. `certificate` is the
// full PEM chain (leaf + intermediates) base64-encoded; `key` is the
// private key in PEM form, also base64-encoded.
type AcmeCertificate struct {
	Domain      AcmeDomain `json:"domain"`
	Certificate string     `json:"certificate"`
	Key         string     `json:"key"`
	Store       string     `json:"Store,omitempty"`
}

// AcmeDomain is the SAN list for a single certificate. `Main` is the CN;
// `SANs` are any additional names covered by the same cert.
type AcmeDomain struct {
	Main string   `json:"main"`
	SANs []string `json:"sans,omitempty"`
}

// RenderedCert is one (cert, key, names) tuple ready to write to disk.
// Names is the de-duplicated, sorted union of Main and SANs — used both
// for the on-disk filename (via the slug of Main) and for the tls.yml
// hint to Traefik about which hostnames this cert covers (Traefik
// actually picks certs by SNI from the cert itself, but listing them in
// tls.yml makes the config self-documenting).
type RenderedCert struct {
	Main  string
	Names []string
	Cert  []byte // PEM chain
	Key   []byte // PEM private key
}

// ParseAcme decodes raw acme.json bytes into a flat list of certs across
// all resolvers. Order is stable (sorted by Main domain) so identical
// inputs produce identical outputs — important for the content-compare
// dedup that keeps Render event-free when nothing changed.
//
// Certificates missing a Main domain or with empty cert/key material are
// skipped with no error: Traefik sometimes writes placeholder entries
// mid-issuance, and we don't want to crash the renderer on transient
// state. The caller can compare len(out) to the count of entries in the
// raw file if it wants to alert on skips.
func ParseAcme(raw []byte) ([]RenderedCert, error) {
	var f AcmeFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse acme.json: %w", err)
	}

	// De-dup by Main domain — if two resolvers somehow issued for the
	// same name (shouldn't happen with one issuer, but the format
	// permits it), the later one wins. Map keeps it O(n) and the final
	// sort gives stable output.
	byMain := make(map[string]RenderedCert)

	// Walk resolvers in sorted order so when two resolvers carry the
	// same Main, the "later wins" is deterministic.
	resolverNames := make([]string, 0, len(f))
	for name := range f {
		resolverNames = append(resolverNames, name)
	}
	sort.Strings(resolverNames)

	for _, name := range resolverNames {
		for _, c := range f[name].Certificates {
			main := strings.TrimSpace(c.Domain.Main)
			if main == "" || c.Certificate == "" || c.Key == "" {
				continue
			}
			certPEM, err := base64.StdEncoding.DecodeString(c.Certificate)
			if err != nil {
				return nil, fmt.Errorf("decode certificate for %q (resolver %q): %w", main, name, err)
			}
			keyPEM, err := base64.StdEncoding.DecodeString(c.Key)
			if err != nil {
				return nil, fmt.Errorf("decode key for %q (resolver %q): %w", main, name, err)
			}
			byMain[main] = RenderedCert{
				Main:  main,
				Names: dedupSorted(append([]string{main}, c.Domain.SANs...)),
				Cert:  certPEM,
				Key:   keyPEM,
			}
		}
	}

	out := make([]RenderedCert, 0, len(byMain))
	for _, c := range byMain {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Main < out[j].Main })
	return out, nil
}

func dedupSorted(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Render reconciles baseDir/live/ to hold exactly the given certs: one
// .crt and .key per cert plus a tls.yml index that Traefik's file provider
// reads. It reports whether it changed anything on disk.
//
// Gateway Traefik watches baseDir/live/ directly (a real directory, never a
// symlink). All writes are in place via atomic renames from a staging dir,
// and the ordering below keeps every state Traefik can observe internally
// consistent even though the reload can fire between any two file
// operations:
//
//  1. Write/replace every cert .crt/.key first. A reload triggered here
//     still reads the OLD tls.yml, which references only files that already
//     exist — so it's a harmless no-op.
//  2. Write tls.yml last. Its event is the one that makes Traefik pick up
//     the new set, and by then every path it names is on disk.
//  3. Remove files that are no longer referenced, only after tls.yml has
//     stopped pointing at them — so Traefik never sees the index reference
//     a file that's already gone.
//
// Unchanged files are skipped (content compare), so re-rendering identical
// input touches nothing and fires no inotify event — the property that
// keeps a missing/empty acme.json from reloading Traefik every poll.
func Render(baseDir string, certs []RenderedCert) (changed bool, err error) {
	if baseDir == "" {
		return false, fmt.Errorf("render: baseDir is empty")
	}
	liveDir := filepath.Join(baseDir, LiveDirName)
	stagingDir := filepath.Join(baseDir, stagingDirName)
	if err := os.MkdirAll(liveDir, 0o700); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", liveDir, err)
	}
	if err := os.MkdirAll(stagingDir, 0o700); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", stagingDir, err)
	}

	// keep is the set of filenames that must remain in liveDir after this
	// render; anything else is pruned in step 3. tls.yml is always kept.
	keep := map[string]struct{}{"tls.yml": {}}

	// certFile is a rendered file plus its final name in liveDir.
	type certFile struct {
		name string
		data []byte
	}
	var files []certFile

	// tlsEntry is one (certFile, keyFile) pair for the tls.yml index,
	// carrying absolute paths through liveDir. Relative paths don't work:
	// Traefik resolves certFile against its process CWD ("/" in the
	// upstream image), not the directory holding the dynamic config, so a
	// bare filename produces a misleading "unable to parse certificate" at
	// startup.
	type tlsEntry struct{ cert, key string }
	entries := make([]tlsEntry, 0, len(certs))

	usedSlugs := make(map[string]int, len(certs))
	for _, c := range certs {
		slug := slugify(c.Main)
		// Disambiguate collisions deterministically — slugify("a.b") and
		// slugify("a-b") could in principle map to the same string, and
		// two different certs sharing a filename would silently overwrite
		// each other. Tag the second occurrence onward with an index.
		if n, dup := usedSlugs[slug]; dup {
			usedSlugs[slug] = n + 1
			slug = fmt.Sprintf("%s-%d", slug, n+1)
		} else {
			usedSlugs[slug] = 1
		}

		certName, keyName := slug+".crt", slug+".key"
		files = append(files,
			certFile{name: certName, data: c.Cert},
			certFile{name: keyName, data: c.Key},
		)
		keep[certName] = struct{}{}
		keep[keyName] = struct{}{}
		entries = append(entries, tlsEntry{
			cert: filepath.Join(liveDir, certName),
			key:  filepath.Join(liveDir, keyName),
		})
	}

	// Step 1: cert/key material first.
	for _, f := range files {
		wrote, err := writeFileIfChanged(liveDir, stagingDir, f.name, f.data)
		if err != nil {
			return changed, err
		}
		changed = changed || wrote
	}

	// Step 2: the index last.
	var b strings.Builder
	b.WriteString("# generated by certific — do not edit by hand\n")
	b.WriteString("tls:\n")
	if len(entries) == 0 {
		// An empty `certificates:` list is valid YAML; emit an explicit
		// empty sequence so Traefik doesn't warn on a key-with-no-value.
		b.WriteString("  certificates: []\n")
	} else {
		b.WriteString("  certificates:\n")
		for _, e := range entries {
			fmt.Fprintf(&b, "    - certFile: %s\n", e.cert)
			fmt.Fprintf(&b, "      keyFile: %s\n", e.key)
		}
	}
	wroteTLS, err := writeFileIfChanged(liveDir, stagingDir, "tls.yml", []byte(b.String()))
	if err != nil {
		return changed, err
	}
	changed = changed || wroteTLS

	// Step 3: prune anything no longer referenced.
	pruned, err := pruneDir(liveDir, keep)
	if err != nil {
		return changed, err
	}
	changed = changed || pruned

	return changed, nil
}

// writeFileIfChanged writes data to <liveDir>/<name> only when the current
// content differs, reporting whether it wrote. The write goes to a temp
// file in stagingDir and is renamed into liveDir — atomic on the shared
// filesystem, so a directory watcher never observes a partial file and no
// temp file is ever visible inside the watched liveDir. Skipping unchanged
// files is what keeps a re-render of identical input event-free.
//
// Mode is forced to 0600 (private keys live here) regardless of umask or a
// leftover temp file from a crashed prior run.
func writeFileIfChanged(liveDir, stagingDir, name string, data []byte) (bool, error) {
	dst := filepath.Join(liveDir, name)
	if existing, err := os.ReadFile(dst); err == nil && bytes.Equal(existing, data) {
		return false, nil
	}
	tmp := filepath.Join(stagingDir, name+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return false, fmt.Errorf("write staging %s: %w", tmp, err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return false, fmt.Errorf("chmod %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return false, fmt.Errorf("rename %s -> %s: %w", tmp, dst, err)
	}
	return true, nil
}

// pruneDir removes every regular file in liveDir whose name is not in keep,
// reporting whether it removed anything. Called after tls.yml has been
// updated to no longer reference the removed certs, so a watcher-triggered
// reload never sees the index point at a file that's already gone.
func pruneDir(liveDir string, keep map[string]struct{}) (bool, error) {
	ents, err := os.ReadDir(liveDir)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", liveDir, err)
	}
	removed := false
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		if _, ok := keep[e.Name()]; ok {
			continue
		}
		if err := os.Remove(filepath.Join(liveDir, e.Name())); err != nil {
			return removed, fmt.Errorf("remove stale %s: %w", e.Name(), err)
		}
		removed = true
	}
	return removed, nil
}

// slugify maps a hostname to a filesystem-safe filename stem. Wildcards
// (`*.example.com`) get a `_wildcard.` prefix because `*` is legal on
// most filesystems but trips shell globbing and is a footgun in
// operator-pasted commands.
func slugify(host string) string {
	s := strings.TrimSpace(host)
	if strings.HasPrefix(s, "*.") {
		s = "_wildcard." + s[2:]
	}
	// Keep dots and dashes (they're already shell-safe and read well);
	// replace anything else with `_`. This matters very rarely — host
	// names containing other chars aren't valid DNS — but defensive
	// because acme.json can carry whatever the issuer was asked to mint.
	var out strings.Builder
	out.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			out.WriteRune(r)
		default:
			out.WriteRune('_')
		}
	}
	return out.String()
}
