package certific

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

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
// inputs produce identical outputs — important for the content-hash
// dedup in the downloader.
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

// Render writes a versioned snapshot of certs to baseDir/versions/<id>/
// and atomically swaps the baseDir/current symlink to point at it.
// Traefik's file provider, pointed at baseDir/current, sees a consistent
// directory at all times — either fully the old snapshot or fully the
// new one.
//
// The version id encodes wall-clock time plus a content hash so:
//   - lexicographic sort matches chronological order (useful for pruning),
//   - the same input produces the same id (idempotent re-render is a
//     cheap no-op when nothing changed),
//   - operators can eyeball "when was this version cut" from `ls`.
//
// keep is the number of previous versions to retain after a successful
// swap. Older ones are removed; failures to remove are logged-and-skipped
// by the caller (Render itself just returns the list of stale dirs).
func Render(baseDir string, certs []RenderedCert, keep int) (versionDir string, pruned []string, err error) {
	if baseDir == "" {
		return "", nil, fmt.Errorf("render: baseDir is empty")
	}
	versionsRoot := filepath.Join(baseDir, "versions")
	if err := os.MkdirAll(versionsRoot, 0o700); err != nil {
		return "", nil, fmt.Errorf("mkdir %s: %w", versionsRoot, err)
	}

	id := versionID(certs)
	versionDir = filepath.Join(versionsRoot, id)

	// If a directory with this exact id already exists, it's the
	// finished output of a previous identical render. Trust it: skip
	// re-writing files, but still re-point `current` in case a prior
	// run was interrupted between writing files and updating the
	// symlink.
	if _, statErr := os.Stat(versionDir); statErr == nil {
		if err := swapCurrent(baseDir, versionDir); err != nil {
			return "", nil, err
		}
		pruned, _ = pruneVersions(versionsRoot, id, keep)
		return versionDir, pruned, nil
	}

	// Stage into a sibling .tmp dir, then rename onto the final name.
	// A crash mid-render leaves the .tmp orphan behind (cleaned up on
	// the next pruneVersions sweep) but never a half-written version
	// dir under its final name.
	stagingDir := versionDir + ".tmp"
	if err := os.RemoveAll(stagingDir); err != nil {
		return "", nil, fmt.Errorf("clean staging dir: %w", err)
	}
	if err := os.MkdirAll(stagingDir, 0o700); err != nil {
		return "", nil, fmt.Errorf("mkdir staging: %w", err)
	}

	if err := writeCerts(stagingDir, certs); err != nil {
		_ = os.RemoveAll(stagingDir)
		return "", nil, err
	}

	if err := os.Rename(stagingDir, versionDir); err != nil {
		_ = os.RemoveAll(stagingDir)
		return "", nil, fmt.Errorf("rename %s -> %s: %w", stagingDir, versionDir, err)
	}

	if err := swapCurrent(baseDir, versionDir); err != nil {
		return "", nil, err
	}

	pruned, _ = pruneVersions(versionsRoot, id, keep)
	return versionDir, pruned, nil
}

// versionID is "<RFC3339-ish timestamp>-<hash-prefix>". The timestamp
// gives chronological ordering; the hash gives content-addressing so
// re-rendering the same certs is a no-op. Hash is over the canonical
// (sorted) cert list, not the original acme.json bytes — that way an
// unrelated change inside acme.json (e.g. ACME account metadata) doesn't
// force a re-render.
func versionID(certs []RenderedCert) string {
	h := sha256.New()
	for _, c := range certs {
		// Length-prefix each field so concatenation can't collide.
		fmt.Fprintf(h, "%d:%s\n", len(c.Main), c.Main)
		for _, n := range c.Names {
			fmt.Fprintf(h, "%d:%s\n", len(n), n)
		}
		fmt.Fprintf(h, "cert:%d\n", len(c.Cert))
		h.Write(c.Cert)
		fmt.Fprintf(h, "key:%d\n", len(c.Key))
		h.Write(c.Key)
	}
	sum := h.Sum(nil)
	ts := time.Now().UTC().Format("20060102T150405Z")
	return ts + "-" + hex.EncodeToString(sum[:6])
}

// writeCerts populates dir with one .crt and .key per cert plus a
// tls.yml index that Traefik's file provider reads. File mode is 0o600
// because the keys are private; the dir is 0o700 (set by caller).
func writeCerts(dir string, certs []RenderedCert) error {
	usedSlugs := make(map[string]int, len(certs))
	type entry struct{ cert, key string }
	entries := make([]entry, 0, len(certs))

	for _, c := range certs {
		slug := slugify(c.Main)
		// Disambiguate collisions deterministically — slugify("a.b") and
		// slugify("a-b") could in principle map to the same string, and
		// two different certs sharing a filename would silently overwrite
		// each other. We tag the second occurrence onward with an index.
		if n, dup := usedSlugs[slug]; dup {
			usedSlugs[slug] = n + 1
			slug = fmt.Sprintf("%s-%d", slug, n+1)
		} else {
			usedSlugs[slug] = 1
		}

		certPath := filepath.Join(dir, slug+".crt")
		keyPath := filepath.Join(dir, slug+".key")

		if err := os.WriteFile(certPath, c.Cert, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", certPath, err)
		}
		if err := os.WriteFile(keyPath, c.Key, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", keyPath, err)
		}
		entries = append(entries, entry{cert: slug + ".crt", key: slug + ".key"})
	}

	// Traefik dynamic config schema: a top-level `tls.certificates` list
	// where each entry points at certFile + keyFile (paths relative to
	// Traefik's working directory, but the file provider resolves them
	// against the directory containing the dynamic config — which is
	// `current` after the symlink swap). YAML is hand-emitted to avoid
	// pulling in a YAML dependency for ~20 lines of output.
	var b strings.Builder
	b.WriteString("# generated by certific — do not edit by hand\n")
	b.WriteString("tls:\n")
	b.WriteString("  certificates:\n")
	for _, e := range entries {
		fmt.Fprintf(&b, "    - certFile: %s\n", e.cert)
		fmt.Fprintf(&b, "      keyFile: %s\n", e.key)
	}
	if len(entries) == 0 {
		// An empty `certificates:` list under `tls:` is valid YAML but
		// some parsers prefer an explicit empty sequence. Emit one so
		// Traefik doesn't warn on a key-with-no-value.
		// Replace the trailing "  certificates:\n" with "  certificates: []\n".
		out := strings.TrimSuffix(b.String(), "  certificates:\n") + "  certificates: []\n"
		return os.WriteFile(filepath.Join(dir, "tls.yml"), []byte(out), 0o600)
	}

	return os.WriteFile(filepath.Join(dir, "tls.yml"), []byte(b.String()), 0o600)
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

// swapCurrent atomically points baseDir/current at target. The standard
// pattern: write a sibling symlink (current.new), then rename it onto
// `current`. Same-directory rename is atomic on POSIX filesystems, so
// Traefik either sees the old target or the new one, never neither.
//
// The new symlink's target is stored as a relative path (`versions/X`)
// rather than absolute so the whole baseDir can be moved (e.g. mounted
// at a different path inside Traefik's container vs. on the host)
// without invalidating the link.
func swapCurrent(baseDir, target string) error {
	rel, err := filepath.Rel(baseDir, target)
	if err != nil {
		return fmt.Errorf("relpath %s -> %s: %w", baseDir, target, err)
	}
	currentPath := filepath.Join(baseDir, "current")
	tmpLink := currentPath + ".new"

	// Remove any leftover tmpLink from a prior crash so Symlink doesn't
	// fail with EEXIST.
	_ = os.Remove(tmpLink)

	if err := os.Symlink(rel, tmpLink); err != nil {
		return fmt.Errorf("symlink %s -> %s: %w", tmpLink, rel, err)
	}
	if err := os.Rename(tmpLink, currentPath); err != nil {
		_ = os.Remove(tmpLink)
		return fmt.Errorf("rename %s -> %s: %w", tmpLink, currentPath, err)
	}
	return nil
}

// pruneVersions deletes versioned snapshots older than the most recent
// `keep` (excluding the active one). Returns the directories that were
// removed; errors removing any single one are swallowed and skipped so a
// stuck file lock on one snapshot doesn't block pruning the rest.
//
// Also cleans up stray `*.tmp` staging dirs from crashed renders.
func pruneVersions(versionsRoot, activeID string, keep int) ([]string, error) {
	entries, err := os.ReadDir(versionsRoot)
	if err != nil {
		return nil, err
	}
	// Collect finished versions; remove stray .tmp dirs unconditionally
	// (they're either a crash residue or our own current staging dir,
	// and our own is already renamed away by the time we get here).
	var versions []string
	var removed []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".tmp") {
			p := filepath.Join(versionsRoot, name)
			if err := os.RemoveAll(p); err == nil {
				removed = append(removed, p)
			}
			continue
		}
		versions = append(versions, name)
	}
	// Sort ascending; the version id encodes a timestamp first, so this
	// is also chronological. Drop the active id from the deletion list.
	sort.Strings(versions)
	var deletable []string
	for _, v := range versions {
		if v == activeID {
			continue
		}
		deletable = append(deletable, v)
	}
	// Keep the most recent `keep` non-active versions; delete the rest.
	if keep < 0 {
		keep = 0
	}
	if len(deletable) <= keep {
		return removed, nil
	}
	toDelete := deletable[:len(deletable)-keep]
	for _, v := range toDelete {
		p := filepath.Join(versionsRoot, v)
		if err := os.RemoveAll(p); err == nil {
			removed = append(removed, p)
		}
	}
	return removed, nil
}
