// Package contract holds the enrollment contract between the hub and this
// client, and nothing else.
//
// The hub answers in Python and this client parses in Go. Nothing catches a
// mismatch between them at compile time, so the shapes live as data rather
// than in either side's source. A field added on one side alone fails a test
// on both.
//
// These files are a copy. The contract is written in contracts/enrollment at
// the top of the repository, where the Python suites read it. The copy exists
// because Go's test cache does not track a file outside the module: a Go test
// that read the contract by path went on reporting a stale pass after the
// contract changed, which is the exact way this check decays without anyone
// noticing. Embedding makes each file a build input, so changing one changes
// the package's build ID and every test that depends on it runs again.
//
// The copy is not a second opinion. TestTheGoModulesCopyIsHonest in
// tests/test_wireguard_contract.py asserts the two directories are byte for
// byte identical, and pytest has no cache to go stale on. Change a file in
// contracts/enrollment and copy it here in the same commit.
package contract

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed fields.json
var fieldsJSON []byte

//go:embed request.json
var requestJSON []byte

//go:embed response.json
var responseJSON []byte

//go:embed error.json
var errorJSON []byte

//go:embed refresh-request.json
var refreshRequestJSON []byte

//go:embed refresh-response.json
var refreshResponseJSON []byte

// Field is one field of the request or the response.
type Field struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
}

// Side is one direction of the exchange.
type Side struct {
	PythonModel string  `json:"python_model"`
	GoType      string  `json:"go_type"`
	Fields      []Field `json:"fields"`
}

// Endpoint is where and how the exchange happens.
type Endpoint struct {
	Method        string `json:"method"`
	Path          string `json:"path"`
	SuccessStatus int    `json:"success_status"`
}

// Manifest is the whole contract.
type Manifest struct {
	Endpoint        Endpoint `json:"endpoint"`
	ExampleSecret   string   `json:"example_secret"`
	Request         Side     `json:"request"`
	Response        Side     `json:"response"`
	RefreshEndpoint Endpoint `json:"refresh_endpoint"`
	RefreshRequest  Side     `json:"refresh_request"`
	RefreshResponse Side     `json:"refresh_response"`
}

// Load returns the contract manifest.
func Load() (Manifest, error) {
	var manifest Manifest
	if err := json.Unmarshal(fieldsJSON, &manifest); err != nil {
		return manifest, fmt.Errorf("parsing fields.json: %w", err)
	}
	return manifest, nil
}

// RequestFixture is the worked example of an enrollment request.
func RequestFixture() []byte { return requestJSON }

// ResponseFixture is the worked example of the hub's answer. Its MAC covers
// the nonce in RequestFixture.
func ResponseFixture() []byte { return responseJSON }

// ErrorFixture is the worked example of a refused enrollment: one sentence
// under "detail". A client that cannot read this shape has nothing to tell the
// operator when the hub says no.
func ErrorFixture() []byte { return errorJSON }

// RefreshRequestFixture is the worked request from an enrolled node.
func RefreshRequestFixture() []byte { return refreshRequestJSON }

// RefreshResponseFixture is the matching signed answer.
func RefreshResponseFixture() []byte { return refreshResponseJSON }
