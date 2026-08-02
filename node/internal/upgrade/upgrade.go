// Package upgrade resolves a published release and fetches its package, so a
// router can move to a new version without being uninstalled and rejoined.
package upgrade

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// Release is one published version: the tag the artifacts hang off, and the
// version as it appears in a package filename.
type Release struct {
	Tag     string
	Version string
}

// maxPackage bounds a download. The node package is a few megabytes, so
// anything past this is a wrong URL or a hostile answer rather than a release.
const maxPackage = 64 << 20

// maxChecksums bounds the SHA256SUMS read, which is a few hundred bytes.
const maxChecksums = 1 << 20

// Resolve turns a wanted version into a release. An empty version asks GitHub
// for the latest one, which is the case that lets an operator update without
// having to look a version number up first.
func Resolve(ctx context.Context, client *http.Client, repo, wanted string) (Release, error) {
	if wanted != "" {
		return Release{Tag: wanted, Version: strings.TrimPrefix(wanted, "v")}, nil
	}
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Release{}, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	response, err := client.Do(request)
	if err != nil {
		return Release{}, fmt.Errorf("asking %s for its latest release: %w", repo, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Release{}, fmt.Errorf(
			"%s has no latest release to report: HTTP %d", repo, response.StatusCode)
	}
	var answer struct {
		Tag string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxChecksums)).Decode(&answer); err != nil {
		return Release{}, fmt.Errorf("reading the latest release of %s: %w", repo, err)
	}
	if answer.Tag == "" {
		return Release{}, fmt.Errorf("the latest release of %s has no tag", repo)
	}
	return Release{Tag: answer.Tag, Version: strings.TrimPrefix(answer.Tag, "v")}, nil
}

// Published reports whether a release really carries this artifact. Resolve
// takes an explicit version on trust, because a version is not a question that
// can be answered without asking, so a check that says nothing about whether
// the release exists would be worse than no check at all.
func Published(ctx context.Context, client *http.Client, repo string, release Release, file string) error {
	url := fmt.Sprintf("https://github.com/%s/releases/download/%s/SHA256SUMS", repo, release.Tag)
	sums, err := body(ctx, client, url, maxChecksums)
	if err != nil {
		return fmt.Errorf("%s has no release %s: %w", repo, release.Tag, err)
	}
	_, err = checksumFor(string(sums), file)
	return err
}

// Fetch downloads one release artifact to path and checks it against the
// SHA256SUMS published beside it. The checksum is verified before the file is
// handed to a package manager, because that is the step that runs as root.
func Fetch(ctx context.Context, client *http.Client, repo string, release Release, file, path string) error {
	base := fmt.Sprintf("https://github.com/%s/releases/download/%s", repo, release.Tag)

	sums, err := body(ctx, client, base+"/SHA256SUMS", maxChecksums)
	if err != nil {
		return fmt.Errorf("fetching SHA256SUMS for %s: %w", release.Tag, err)
	}
	wanted, err := checksumFor(string(sums), file)
	if err != nil {
		return err
	}

	packaged, err := body(ctx, client, base+"/"+file, maxPackage)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", file, err)
	}
	sum := sha256.Sum256(packaged)
	if got := hex.EncodeToString(sum[:]); got != wanted {
		return fmt.Errorf(
			"%s does not match its published checksum: got %s, SHA256SUMS says %s", file, got, wanted)
	}
	if err := os.WriteFile(path, packaged, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// checksumFor picks one file out of a sha256sum listing.
func checksumFor(sums, file string) (string, error) {
	for _, line := range strings.Split(sums, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[1] != file {
			continue
		}
		if len(fields[0]) != sha256.Size*2 {
			return "", fmt.Errorf("SHA256SUMS has an unusable checksum for %s", file)
		}
		if _, err := hex.DecodeString(fields[0]); err != nil {
			return "", fmt.Errorf("SHA256SUMS has an unusable checksum for %s", file)
		}
		return strings.ToLower(fields[0]), nil
	}
	return "", fmt.Errorf(
		"SHA256SUMS names no %s, so this release has no package for this router", file)
}

func body(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	return io.ReadAll(io.LimitReader(response.Body, limit))
}
