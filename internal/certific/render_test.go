package certific

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// b64 wraps base64.StdEncoding.EncodeToString for fixture readability.
func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestParseAcmeExtractsCertsAcrossResolvers(t *testing.T) {
	// Two resolvers, three certs total. ParseAcme should return all of
	// them, sorted by Main domain. SANs round-trip through dedupSorted.
	raw := fmt.Sprintf(`{
		"dns": {
			"Account": {"Email":"ops@example.com"},
			"Certificates": [
				{"domain":{"main":"a.example","sans":["www.a.example","a.example"]},"certificate":%q,"key":%q},
				{"domain":{"main":"c.example"},"certificate":%q,"key":%q}
			]
		},
		"http": {
			"Account": {},
			"Certificates": [
				{"domain":{"main":"b.example"},"certificate":%q,"key":%q}
			]
		}
	}`,
		b64("certA"), b64("keyA"),
		b64("certC"), b64("keyC"),
		b64("certB"), b64("keyB"),
	)

	certs, err := ParseAcme([]byte(raw))
	if err != nil {
		t.Fatalf("ParseAcme: %v", err)
	}
	if len(certs) != 3 {
		t.Fatalf("len(certs) = %d, want 3", len(certs))
	}
	wantOrder := []string{"a.example", "b.example", "c.example"}
	for i, w := range wantOrder {
		if certs[i].Main != w {
			t.Errorf("certs[%d].Main = %q, want %q", i, certs[i].Main, w)
		}
	}

	// SANs for a.example should be deduplicated (the main domain was
	// also in the SAN list, exercising the dedup path).
	got := certs[0].Names
	want := []string{"a.example", "www.a.example"}
	if len(got) != len(want) {
		t.Fatalf("a.example Names = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("a.example Names[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	if !bytes.Equal(certs[0].Cert, []byte("certA")) {
		t.Errorf("a.example Cert = %q, want certA", certs[0].Cert)
	}
}

func TestParseAcmeSkipsIncompleteEntries(t *testing.T) {
	// Traefik sometimes writes a placeholder mid-issuance: a domain
	// entry with empty certificate/key bytes. The parser must skip
	// those rather than emit a renderable cert with no material.
	raw := fmt.Sprintf(`{"dns":{"Account":{},"Certificates":[
		{"domain":{"main":""},"certificate":%q,"key":%q},
		{"domain":{"main":"empty-cert.example"},"certificate":"","key":%q},
		{"domain":{"main":"ok.example"},"certificate":%q,"key":%q}
	]}}`, b64("x"), b64("y"), b64("z"), b64("certOK"), b64("keyOK"))

	certs, err := ParseAcme([]byte(raw))
	if err != nil {
		t.Fatalf("ParseAcme: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("len(certs) = %d, want 1 (others should be skipped)", len(certs))
	}
	if certs[0].Main != "ok.example" {
		t.Errorf("kept cert.Main = %q, want ok.example", certs[0].Main)
	}
}

func TestParseAcmeRejectsBadBase64(t *testing.T) {
	// A corrupted acme.json with un-decodable base64 must error out so
	// the downloader logs and retries instead of rendering a broken
	// snapshot.
	raw := `{"dns":{"Account":{},"Certificates":[
		{"domain":{"main":"bad.example"},"certificate":"!!!not-b64!!!","key":"x"}
	]}}`
	if _, err := ParseAcme([]byte(raw)); err == nil {
		t.Fatal("expected error for bad base64")
	}
}

// liveDir is the directory Traefik watches; helper keeps the tests terse.
func liveDir(base string) string { return filepath.Join(base, LiveDirName) }

func TestRenderWritesPEMsAndTLSYAML(t *testing.T) {
	dir := t.TempDir()
	certs := []RenderedCert{
		{Main: "a.example", Names: []string{"a.example"}, Cert: []byte("certA"), Key: []byte("keyA")},
		{Main: "b.example", Names: []string{"b.example"}, Cert: []byte("certB"), Key: []byte("keyB")},
	}

	changed, err := Render(dir, certs)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !changed {
		t.Errorf("first render reported changed=false, want true")
	}

	// live/ must be a real directory, never a symlink — that's the whole
	// point of the in-place design: Traefik's directory watch only fires
	// on events inside a real watched dir, not on a symlink repoint.
	info, err := os.Lstat(liveDir(dir))
	if err != nil {
		t.Fatalf("lstat live: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Errorf("live/ is a symlink; must be a real directory")
	}

	// Both certs are written with their full PEM bytes.
	for _, c := range certs {
		body, err := os.ReadFile(filepath.Join(liveDir(dir), c.Main+".crt"))
		if err != nil {
			t.Fatalf("read %s.crt: %v", c.Main, err)
		}
		if !bytes.Equal(body, c.Cert) {
			t.Errorf("%s.crt = %q, want %q", c.Main, body, c.Cert)
		}
	}

	// tls.yml lists both certs by absolute path through live/. Bare
	// filenames don't work — Traefik resolves relative certFile paths
	// against its process CWD, not the directory containing the dynamic
	// config, and silently fails with a misleading "unable to parse
	// certificate" error. Lock in the path shape so it can't regress.
	tlsYml, err := os.ReadFile(filepath.Join(liveDir(dir), "tls.yml"))
	if err != nil {
		t.Fatalf("read tls.yml: %v", err)
	}
	for _, c := range certs {
		wantCert := fmt.Sprintf("certFile: %s\n", filepath.Join(liveDir(dir), c.Main+".crt"))
		wantKey := fmt.Sprintf("keyFile: %s\n", filepath.Join(liveDir(dir), c.Main+".key"))
		if !bytes.Contains(tlsYml, []byte(wantCert)) {
			t.Errorf("tls.yml missing absolute certFile entry %q; got:\n%s", wantCert, tlsYml)
		}
		if !bytes.Contains(tlsYml, []byte(wantKey)) {
			t.Errorf("tls.yml missing absolute keyFile entry %q; got:\n%s", wantKey, tlsYml)
		}
	}
}

func TestRenderReplacesInPlace(t *testing.T) {
	// Two consecutive renders with different cert content for the same
	// host. The second must overwrite the cert file in live/ (in place —
	// same path, no symlink swap) so a directory watcher sees the change.
	dir := t.TempDir()

	v1 := []RenderedCert{{Main: "x.example", Names: []string{"x.example"}, Cert: []byte("v1"), Key: []byte("k1")}}
	v2 := []RenderedCert{{Main: "x.example", Names: []string{"x.example"}, Cert: []byte("v2"), Key: []byte("k2")}}

	if _, err := Render(dir, v1); err != nil {
		t.Fatalf("Render v1: %v", err)
	}
	certPath := filepath.Join(liveDir(dir), "x.example.crt")
	got, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read v1 cert: %v", err)
	}
	if !bytes.Equal(got, []byte("v1")) {
		t.Errorf("after v1: got %q, want v1", got)
	}

	if _, err := Render(dir, v2); err != nil {
		t.Fatalf("Render v2: %v", err)
	}
	got, err = os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read v2 cert: %v", err)
	}
	if !bytes.Equal(got, []byte("v2")) {
		t.Errorf("after v2: got %q, want v2", got)
	}
}

func TestRenderPrunesRemovedCerts(t *testing.T) {
	// A host present in one render but gone from the next must have its
	// .crt/.key removed from live/ — otherwise a decommissioned domain's
	// key material lingers on every gateway indefinitely.
	dir := t.TempDir()

	two := []RenderedCert{
		{Main: "keep.example", Names: []string{"keep.example"}, Cert: []byte("kc"), Key: []byte("kk")},
		{Main: "drop.example", Names: []string{"drop.example"}, Cert: []byte("dc"), Key: []byte("dk")},
	}
	if _, err := Render(dir, two); err != nil {
		t.Fatalf("Render two: %v", err)
	}
	// Sanity: both are present.
	for _, name := range []string{"keep.example.crt", "drop.example.crt"} {
		if _, err := os.Stat(filepath.Join(liveDir(dir), name)); err != nil {
			t.Fatalf("expected %s present: %v", name, err)
		}
	}

	one := []RenderedCert{
		{Main: "keep.example", Names: []string{"keep.example"}, Cert: []byte("kc"), Key: []byte("kk")},
	}
	changed, err := Render(dir, one)
	if err != nil {
		t.Fatalf("Render one: %v", err)
	}
	if !changed {
		t.Errorf("dropping a cert reported changed=false, want true")
	}
	for _, name := range []string{"drop.example.crt", "drop.example.key"} {
		if _, err := os.Stat(filepath.Join(liveDir(dir), name)); !os.IsNotExist(err) {
			t.Errorf("expected %s pruned, stat err = %v", name, err)
		}
	}
	// The retained cert and the index survive.
	if _, err := os.Stat(filepath.Join(liveDir(dir), "keep.example.crt")); err != nil {
		t.Errorf("keep.example.crt should survive: %v", err)
	}
	if _, err := os.Stat(filepath.Join(liveDir(dir), "tls.yml")); err != nil {
		t.Errorf("tls.yml should survive: %v", err)
	}
}

func TestRenderIdempotentForSameInput(t *testing.T) {
	// Rendering the same cert list twice must be a no-op the second time:
	// no file is rewritten, so no inotify event fires and Traefik doesn't
	// reload. This is what keeps a re-Get with identical cert material (or
	// the every-cycle empty re-render) from churning Traefik.
	dir := t.TempDir()
	certs := []RenderedCert{
		{Main: "z.example", Names: []string{"z.example"}, Cert: []byte("same"), Key: []byte("samek")},
	}
	changed1, err := Render(dir, certs)
	if err != nil {
		t.Fatalf("Render 1: %v", err)
	}
	if !changed1 {
		t.Errorf("first render changed=false, want true")
	}

	// Capture mtimes; a true no-op must not touch any file.
	before := fileMTimes(t, liveDir(dir))

	changed2, err := Render(dir, certs)
	if err != nil {
		t.Fatalf("Render 2: %v", err)
	}
	if changed2 {
		t.Errorf("second identical render changed=true, want false (no-op)")
	}
	after := fileMTimes(t, liveDir(dir))

	for name, mt := range before {
		if after[name] != mt {
			t.Errorf("%s was rewritten on an identical render (mtime changed)", name)
		}
	}
}

func fileMTimes(t *testing.T, dir string) map[string]int64 {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir %s: %v", dir, err)
	}
	out := make(map[string]int64, len(ents))
	for _, e := range ents {
		info, err := e.Info()
		if err != nil {
			t.Fatalf("info %s: %v", e.Name(), err)
		}
		out[e.Name()] = info.ModTime().UnixNano()
	}
	return out
}

func TestRenderEmptyCertsProducesEmptyTLSConfig(t *testing.T) {
	// Edge case: acme.json with no usable certs (first deploy, before
	// any issuance). The renderer must still produce a valid tls.yml
	// so Traefik's file provider doesn't complain about a missing file.
	dir := t.TempDir()
	if _, err := Render(dir, nil); err != nil {
		t.Fatalf("Render: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(liveDir(dir), "tls.yml"))
	if err != nil {
		t.Fatalf("read tls.yml: %v", err)
	}
	if !bytes.Contains(body, []byte("certificates: []")) {
		t.Errorf("expected empty certs list, got: %s", body)
	}
}

func TestRenderLeavesNoStagingResidue(t *testing.T) {
	// The staging dir must never leak temp files: they'd accumulate, and
	// a leftover .tmp under a watched dir would trip Traefik. .staging is
	// a sibling of live/, so it's never watched, but it must still be
	// clean after a successful render.
	dir := t.TempDir()
	certs := []RenderedCert{
		{Main: "s.example", Names: []string{"s.example"}, Cert: []byte("c"), Key: []byte("k")},
	}
	if _, err := Render(dir, certs); err != nil {
		t.Fatalf("Render: %v", err)
	}
	ents, err := os.ReadDir(filepath.Join(dir, stagingDirName))
	if err != nil {
		t.Fatalf("read staging: %v", err)
	}
	if len(ents) != 0 {
		t.Errorf("staging dir not empty after render: %d entries", len(ents))
	}
}

func TestSlugifyWildcard(t *testing.T) {
	// `*.example.com` is a legal SAN but `*` is a footgun in operator
	// commands; the slug should use `_wildcard.` instead.
	got := slugify("*.example.com")
	want := "_wildcard.example.com"
	if got != want {
		t.Errorf("slugify(*.example.com) = %q, want %q", got, want)
	}
}
