package upgrade

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// serve stands in for GitHub, answering the two URLs Fetch asks for.
func serve(t *testing.T, files map[string][]byte, sums string) *http.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := filepath.Base(r.URL.Path)
		if name == "SHA256SUMS" {
			fmt.Fprint(w, sums)
			return
		}
		body, known := files[name]
		if !known {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	t.Cleanup(server.Close)
	client := server.Client()
	client.Transport = rewrite{server.URL, client.Transport}
	return client
}

// rewrite sends every request to the test server, whatever host it names.
type rewrite struct {
	base string
	next http.RoundTripper
}

func (t rewrite) RoundTrip(r *http.Request) (*http.Response, error) {
	replacement, err := http.NewRequestWithContext(r.Context(), r.Method,
		t.base+r.URL.Path, r.Body)
	if err != nil {
		return nil, err
	}
	return t.next.RoundTrip(replacement)
}

func sumsFor(name string, body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]) + "  " + name + "\n"
}

func TestFetchWritesAPackageThatMatchesItsChecksum(t *testing.T) {
	body := []byte("a package, near enough")
	name := "shadow9-node_0.2.0-r1_x86_64.ipk"
	client := serve(t, map[string][]byte{name: body}, sumsFor(name, body))
	path := filepath.Join(t.TempDir(), name)

	err := Fetch(context.Background(), client, "owner/repo", Release{Tag: "v0.2.0"}, name, path)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(body) {
		t.Fatalf("the package on disk is %q, err=%v", got, err)
	}
}

// The checksum is the only thing standing between a wrong answer and a package
// installed as root, so a mismatch must never reach the disk.
func TestFetchRefusesAPackageThatDoesNotMatch(t *testing.T) {
	name := "shadow9-node_0.2.0-r1_x86_64.ipk"
	client := serve(t, map[string][]byte{name: []byte("not what was published")},
		sumsFor(name, []byte("what was published")))
	path := filepath.Join(t.TempDir(), name)

	err := Fetch(context.Background(), client, "owner/repo", Release{Tag: "v0.2.0"}, name, path)
	if err == nil || !strings.Contains(err.Error(), "does not match its published checksum") {
		t.Fatalf("Fetch returned %v", err)
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("a package that failed its checksum was written to disk anyway")
	}
}

func TestFetchRefusesAReleaseWithNoPackageForThisRouter(t *testing.T) {
	other := "shadow9-node_0.2.0-r1_aarch64_generic.ipk"
	client := serve(t, map[string][]byte{}, sumsFor(other, []byte("elsewhere")))
	path := filepath.Join(t.TempDir(), "wanted.ipk")

	err := Fetch(context.Background(), client, "owner/repo", Release{Tag: "v0.2.0"},
		"shadow9-node_0.2.0-r1_x86_64.ipk", path)
	if err == nil || !strings.Contains(err.Error(), "no package for this router") {
		t.Fatalf("Fetch returned %v", err)
	}
}

// Resolve takes an explicit version on trust, so a check has to confirm the
// release really carries the artifact. Reporting a version as available and
// then failing on the download is worse than refusing up front.
func TestPublishedRefusesAVersionThatDoesNotExist(t *testing.T) {
	name := "shadow9-node_0.2.0-r1_x86_64.ipk"
	client := serve(t, map[string][]byte{name: []byte("real")}, sumsFor(name, []byte("real")))

	if err := Published(context.Background(), client, "owner/repo",
		Release{Tag: "v0.2.0"}, name); err != nil {
		t.Errorf("a published artifact was reported missing: %v", err)
	}

	err := Published(context.Background(), client, "owner/repo",
		Release{Tag: "v9.9.9"}, "shadow9-node_9.9.9-r1_x86_64.ipk")
	if err == nil {
		t.Fatal("a version that was never released was reported as available")
	}
}

func TestResolveTakesAnExplicitVersionWithoutAskingGitHub(t *testing.T) {
	client := serve(t, nil, "")
	for _, wanted := range []string{"v0.2.0", "0.2.0"} {
		release, err := Resolve(context.Background(), client, "owner/repo", wanted)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", wanted, err)
		}
		if release.Version != "0.2.0" {
			t.Errorf("Resolve(%q) gave version %q", wanted, release.Version)
		}
	}
}

func TestResolveReadsTheLatestTag(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"tag_name":"v0.3.1"}`)
	}))
	defer server.Close()
	client := server.Client()
	client.Transport = rewrite{server.URL, client.Transport}

	release, err := Resolve(context.Background(), client, "owner/repo", "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if release.Tag != "v0.3.1" || release.Version != "0.3.1" {
		t.Errorf("Resolve gave tag %q version %q", release.Tag, release.Version)
	}
}
