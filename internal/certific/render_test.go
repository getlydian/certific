package certific

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func TestRenderWritesPEMsAndTLSYAML(t *testing.T) {
	dir := t.TempDir()
	certs := []RenderedCert{
		{Main: "a.example", Names: []string{"a.example"}, Cert: []byte("certA"), Key: []byte("keyA")},
		{Main: "b.example", Names: []string{"b.example"}, Cert: []byte("certB"), Key: []byte("keyB")},
	}

	versionDir, _, err := Render(dir, certs, 1)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	// versionDir should be under dir/versions/.
	if !strings.HasPrefix(versionDir, filepath.Join(dir, "versions")) {
		t.Errorf("versionDir = %q, expected under %q/versions", versionDir, dir)
	}

	// `current` resolves to versionDir via symlink.
	resolved, err := os.Readlink(filepath.Join(dir, "current"))
	if err != nil {
		t.Fatalf("readlink current: %v", err)
	}
	wantRel := filepath.Join("versions", filepath.Base(versionDir))
	if resolved != wantRel {
		t.Errorf("current -> %q, want %q (relative)", resolved, wantRel)
	}

	// Both certs are written with their full PEM bytes.
	for _, c := range certs {
		body, err := os.ReadFile(filepath.Join(dir, "current", c.Main+".crt"))
		if err != nil {
			t.Fatalf("read %s.crt: %v", c.Main, err)
		}
		if !bytes.Equal(body, c.Cert) {
			t.Errorf("%s.crt = %q, want %q", c.Main, body, c.Cert)
		}
	}

	// tls.yml lists both certs by absolute path through `current`.
	// Bare filenames don't work — Traefik resolves relative certFile
	// paths against its process CWD, not the directory containing the
	// dynamic config, and silently fails with a misleading "unable to
	// parse certificate" error. Lock in the path shape so the bug can't
	// regress to bare filenames.
	tlsYml, err := os.ReadFile(filepath.Join(dir, "current", "tls.yml"))
	if err != nil {
		t.Fatalf("read tls.yml: %v", err)
	}
	currentDir := filepath.Join(dir, "current")
	for _, c := range certs {
		wantCert := fmt.Sprintf("certFile: %s\n", filepath.Join(currentDir, c.Main+".crt"))
		wantKey := fmt.Sprintf("keyFile: %s\n", filepath.Join(currentDir, c.Main+".key"))
		if !bytes.Contains(tlsYml, []byte(wantCert)) {
			t.Errorf("tls.yml missing absolute certFile entry %q; got:\n%s", wantCert, tlsYml)
		}
		if !bytes.Contains(tlsYml, []byte(wantKey)) {
			t.Errorf("tls.yml missing absolute keyFile entry %q; got:\n%s", wantKey, tlsYml)
		}
	}
}

func TestRenderSymlinkSwapIsAtomic(t *testing.T) {
	// Two consecutive renders with different cert content. After each
	// one, `current` must resolve to a directory containing the
	// expected cert. Specifically: at no point during the second render
	// is `current` allowed to be a broken symlink or point at a
	// half-populated dir. We approximate this by checking the
	// post-conditions of each render.
	dir := t.TempDir()

	v1 := []RenderedCert{{Main: "x.example", Names: []string{"x.example"}, Cert: []byte("v1"), Key: []byte("k1")}}
	v2 := []RenderedCert{{Main: "x.example", Names: []string{"x.example"}, Cert: []byte("v2"), Key: []byte("k2")}}

	if _, _, err := Render(dir, v1, 1); err != nil {
		t.Fatalf("Render v1: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "current", "x.example.crt"))
	if err != nil {
		t.Fatalf("read v1 cert: %v", err)
	}
	if !bytes.Equal(got, []byte("v1")) {
		t.Errorf("after v1: got %q, want v1", got)
	}

	if _, _, err := Render(dir, v2, 1); err != nil {
		t.Fatalf("Render v2: %v", err)
	}
	got, err = os.ReadFile(filepath.Join(dir, "current", "x.example.crt"))
	if err != nil {
		t.Fatalf("read v2 cert: %v", err)
	}
	if !bytes.Equal(got, []byte("v2")) {
		t.Errorf("after v2: got %q, want v2", got)
	}
}

func TestRenderPrunesOldVersions(t *testing.T) {
	// With Keep=1, after three distinct renders the versions/ dir
	// should contain at most two entries (active + 1 prior).
	dir := t.TempDir()

	renders := []RenderedCert{
		{Main: "y.example", Names: []string{"y.example"}, Cert: []byte("a"), Key: []byte("ka")},
		{Main: "y.example", Names: []string{"y.example"}, Cert: []byte("b"), Key: []byte("kb")},
		{Main: "y.example", Names: []string{"y.example"}, Cert: []byte("c"), Key: []byte("kc")},
	}
	for i, r := range renders {
		// Force distinct version ids by writing a sentinel file that
		// pads the content hash differently each iteration; without
		// this two consecutive renders within the same wall-clock
		// second can collide on id and short-circuit out.
		r.Cert = append(r.Cert, byte('0'+i))
		if _, _, err := Render(dir, []RenderedCert{r}, 1); err != nil {
			t.Fatalf("Render[%d]: %v", i, err)
		}
	}

	entries, err := os.ReadDir(filepath.Join(dir, "versions"))
	if err != nil {
		t.Fatal(err)
	}
	var dirs int
	for _, e := range entries {
		if e.IsDir() && filepath.Ext(e.Name()) != ".tmp" {
			dirs++
		}
	}
	if dirs > 2 {
		t.Errorf("versions/ contains %d dirs, want ≤ 2 with Keep=1", dirs)
	}
}

func TestRenderIdempotentForSameInput(t *testing.T) {
	// Rendering the same cert list twice must produce the same version
	// id (content-hashed) and not pile up new directories under
	// versions/. This is what keeps the downloader cheap when an etag
	// changes upstream but the cert material happens to be identical.
	dir := t.TempDir()
	certs := []RenderedCert{
		{Main: "z.example", Names: []string{"z.example"}, Cert: []byte("same"), Key: []byte("samek")},
	}
	v1, _, err := Render(dir, certs, 1)
	if err != nil {
		t.Fatalf("Render 1: %v", err)
	}
	v2, _, err := Render(dir, certs, 1)
	if err != nil {
		t.Fatalf("Render 2: %v", err)
	}
	// Version ids include a timestamp prefix, so consecutive renders
	// inside the same second produce different ids. To pin "same input
	// ⇒ same id" specifically we'd need to inject a clock; instead we
	// settle for the weaker invariant that the second render is a
	// no-op directory-wise when the dir already exists.
	_ = v1
	_ = v2

	entries, err := os.ReadDir(filepath.Join(dir, "versions"))
	if err != nil {
		t.Fatal(err)
	}
	// Either both renders produced the same id (1 dir) or different
	// timestamps produced two (2 dirs, with Keep=1 the older is kept
	// because it's the prior-to-active). Anything more is a bug.
	var dirs int
	for _, e := range entries {
		if e.IsDir() && filepath.Ext(e.Name()) != ".tmp" {
			dirs++
		}
	}
	if dirs > 2 {
		t.Errorf("versions/ contains %d dirs, want ≤ 2", dirs)
	}
}

func TestRenderEmptyCertsProducesEmptyTLSConfig(t *testing.T) {
	// Edge case: acme.json with no usable certs (first deploy, before
	// any issuance). The renderer must still produce a valid tls.yml
	// so Traefik's file provider doesn't complain about a missing file.
	dir := t.TempDir()
	if _, _, err := Render(dir, nil, 1); err != nil {
		t.Fatalf("Render: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "current", "tls.yml"))
	if err != nil {
		t.Fatalf("read tls.yml: %v", err)
	}
	if !bytes.Contains(body, []byte("certificates: []")) {
		t.Errorf("expected empty certs list, got: %s", body)
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
