package enroll

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"shadow9-node/internal/contract"
)

// The enrollment contract is a specified artifact. It is written in
// contracts/enrollment at the top of the repository, where the Python suites
// read it, and internal/contract embeds a byte-identical copy so Go's test
// cache treats it as a build input. Either way both sides are checked against
// the same bytes, so a field added to one side alone fails a test on both.
//
// Working against a live hub proves nothing about drift, because a hub and a
// node that drifted together still agree with each other.

func manifest(t *testing.T) contract.Manifest {
	t.Helper()
	loaded, err := contract.Load()
	if err != nil {
		t.Fatalf("loading the contract: %v", err)
	}
	return loaded
}

// goFields lists a struct's JSON field names and types in declaration order.
func goFields(t *testing.T, value any) []contract.Field {
	t.Helper()
	kind := reflect.TypeOf(value)
	fields := make([]contract.Field, 0, kind.NumField())
	for i := 0; i < kind.NumField(); i++ {
		field := kind.Field(i)
		tag := field.Tag.Get("json")
		if tag == "" || tag == "-" {
			t.Fatalf("%s.%s has no json tag, so it is not part of the contract",
				kind.Name(), field.Name)
		}
		name, _, _ := strings.Cut(tag, ",")
		fields = append(fields, contract.Field{Name: name, Type: goTypeName(t, field.Type)})
	}
	return fields
}

func goTypeName(t *testing.T, kind reflect.Type) string {
	t.Helper()
	switch kind.Kind() {
	case reflect.Pointer:
		return goTypeName(t, kind.Elem())
	case reflect.String:
		return "string"
	case reflect.Bool:
		return "boolean"
	case reflect.Int, reflect.Int64:
		return "integer"
	case reflect.Slice:
		if kind.Elem().Kind() == reflect.String {
			return "string[]"
		}
	}
	t.Fatalf("the contract has no name for the Go type %s", kind)
	return ""
}

func assertFieldsMatch(t *testing.T, side string, expected, actual []contract.Field) {
	t.Helper()
	if len(expected) != len(actual) {
		t.Fatalf("the %s has %d fields in Go and %d in internal/contract/fields.json.\n"+
			"Go:       %v\nmanifest: %v\n"+
			"A field added on one side without the other is what this test is for: move the "+
			"manifest, the Go struct, the fixtures and the pydantic model together.",
			side, len(actual), len(expected), names(actual), names(expected))
	}
	for i := range expected {
		if expected[i].Name != actual[i].Name {
			t.Errorf("%s field %d is %q in Go and %q in the manifest",
				side, i, actual[i].Name, expected[i].Name)
		}
		if expected[i].Type != actual[i].Type {
			t.Errorf("%s field %q is %s in Go and %s in the manifest",
				side, actual[i].Name, actual[i].Type, expected[i].Type)
		}
	}
}

func names(fields []contract.Field) []string {
	out := make([]string, len(fields))
	for i, f := range fields {
		out[i] = f.Name
	}
	return out
}

func TestGoStructsMatchTheContractManifest(t *testing.T) {
	m := manifest(t)
	assertFieldsMatch(t, "request", m.Request.Fields, goFields(t, Request{}))
	assertFieldsMatch(t, "response", m.Response.Fields, goFields(t, Response{}))
	assertFieldsMatch(t, "refresh request", m.RefreshRequest.Fields, goFields(t, RefreshRequest{}))
	assertFieldsMatch(t, "refresh response", m.RefreshResponse.Fields, goFields(t, RefreshResponse{}))
}

func TestTheManifestNamesTheGoTypesItDescribes(t *testing.T) {
	m := manifest(t)
	if !strings.HasSuffix(m.Request.GoType, ".Request") {
		t.Errorf("the manifest says the request is %s", m.Request.GoType)
	}
	if !strings.HasSuffix(m.Response.GoType, ".Response") {
		t.Errorf("the manifest says the response is %s", m.Response.GoType)
	}
	if !strings.HasSuffix(m.RefreshRequest.GoType, ".RefreshRequest") {
		t.Errorf("the manifest says the refresh request is %s", m.RefreshRequest.GoType)
	}
	if !strings.HasSuffix(m.RefreshResponse.GoType, ".RefreshResponse") {
		t.Errorf("the manifest says the refresh response is %s", m.RefreshResponse.GoType)
	}
}

func TestTheContractNamesThisEndpoint(t *testing.T) {
	m := manifest(t)
	if m.Endpoint.Path != Path {
		t.Errorf("the client posts to %s and the contract says %s", Path, m.Endpoint.Path)
	}
	if m.Endpoint.Method != "POST" {
		t.Errorf("the contract says the method is %s", m.Endpoint.Method)
	}
	if m.Endpoint.SuccessStatus != 200 {
		t.Errorf("the contract says success is %d", m.Endpoint.SuccessStatus)
	}
	if m.RefreshEndpoint.Path != RefreshPath || m.RefreshEndpoint.Method != "POST" ||
		m.RefreshEndpoint.SuccessStatus != 200 {
		t.Errorf("the refresh endpoint contract is %+v", m.RefreshEndpoint)
	}
}

// The hub sets extra="forbid", so this side rejects unknown fields too. A
// fixture the hub gained a field in fails here until the Go struct gains it.
func TestTheResponseFixtureDecodesWithNothingLeftOver(t *testing.T) {
	var answer Response
	if err := decodeStrict(contract.ResponseFixture(), &answer); err != nil {
		t.Fatalf("decoding response.json: %v", err)
	}
	if answer.Address == "" || answer.HubPublicKey == "" ||
		answer.HubEndpoint == "" || answer.TunnelNetwork == "" ||
		answer.MTU == nil || answer.Keepalive == nil || answer.Protocol == nil || answer.MAC == "" {
		t.Errorf("response.json left a field empty: %+v", answer)
	}
}

func TestTheRequestFixtureDecodesWithNothingLeftOver(t *testing.T) {
	var request Request
	if err := decodeStrict(contract.RequestFixture(), &request); err != nil {
		t.Fatalf("decoding request.json: %v", err)
	}
	if request.TokenID == "" || request.Name == "" || request.PublicKey == "" ||
		request.Nonce == "" || request.MAC == "" {
		t.Errorf("request.json left a required field empty: %+v", request)
	}
}

// What this client sends must be what the fixture says a request looks like,
// key for key. Encoding rather than only decoding catches the direction where
// Go stops emitting a field the hub still requires.
func TestWhatTheClientSendsMatchesTheRequestFixture(t *testing.T) {
	var fixture map[string]any
	if err := json.Unmarshal(contract.RequestFixture(), &fixture); err != nil {
		t.Fatalf("parsing request.json: %v", err)
	}
	sent, err := json.Marshal(Request{
		TokenID: "t", Name: "n", PublicKey: "k", Routes: []string{}, Nonce: "nonce", MAC: "mac",
	})
	if err != nil {
		t.Fatalf("encoding a request: %v", err)
	}
	var produced map[string]any
	if err := json.Unmarshal(sent, &produced); err != nil {
		t.Fatalf("parsing what the client sent: %v", err)
	}
	for name := range fixture {
		if _, present := produced[name]; !present {
			t.Errorf("the client does not send %q, which request.json has", name)
		}
	}
	for name := range produced {
		if _, present := fixture[name]; !present {
			t.Errorf("the client sends %q, which request.json does not have", name)
		}
	}
}

// The hub's routes field is a list with a default of empty. A JSON null is not
// a list and comes back as a 422, so a node with no LAN has to send [].
func TestRoutesAreSentAsAnEmptyListRatherThanNull(t *testing.T) {
	sent, err := json.Marshal(Request{
		TokenID: "t", Name: "n", PublicKey: "k", Routes: []string{}, Nonce: "nonce", MAC: "mac",
	})
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	if got := string(sent); !strings.Contains(got, `"routes":[]`) {
		t.Errorf("a node with no routes sent %s", got)
	}
}

func TestBothMACsMatchTheSharedFixtures(t *testing.T) {
	m := manifest(t)
	var request Request
	if err := decodeStrict(contract.RequestFixture(), &request); err != nil {
		t.Fatalf("decoding request.json: %v", err)
	}
	var response Response
	if err := decodeStrict(contract.ResponseFixture(), &response); err != nil {
		t.Fatalf("decoding response.json: %v", err)
	}
	token, err := ParseToken(request.TokenID + "." + m.ExampleSecret + "." + response.HubPublicKey)
	if err != nil {
		t.Fatalf("building the fixture token: %v", err)
	}
	if request.MAC != request.signature(token.macKey) {
		t.Errorf("request.json has MAC %s, Go produced %s", request.MAC, request.signature(token.macKey))
	}
	if response.MAC != response.signature(token.macKey, request.Nonce) {
		t.Errorf("response.json has MAC %s, Go produced %s",
			response.MAC, response.signature(token.macKey, request.Nonce))
	}
}

func TestRefreshMACsMatchTheSharedFixtures(t *testing.T) {
	m := manifest(t)
	var request RefreshRequest
	if err := decodeStrict(contract.RefreshRequestFixture(), &request); err != nil {
		t.Fatalf("decoding refresh-request.json: %v", err)
	}
	var response RefreshResponse
	if err := decodeStrict(contract.RefreshResponseFixture(), &response); err != nil {
		t.Fatalf("decoding refresh-response.json: %v", err)
	}
	var enrollment Response
	if err := decodeStrict(contract.ResponseFixture(), &enrollment); err != nil {
		t.Fatalf("decoding response.json: %v", err)
	}
	token, err := ParseToken("join-token-id-value." + m.ExampleSecret + "." + enrollment.HubPublicKey)
	if err != nil {
		t.Fatalf("building the fixture token: %v", err)
	}
	key := token.RefreshKey()
	if request.MAC != request.signature(key) {
		t.Errorf("refresh-request.json has MAC %s, Go produced %s", request.MAC, request.signature(key))
	}
	if response.MAC != response.signature(key, request.Nonce) {
		t.Errorf("refresh-response.json has MAC %s, Go produced %s",
			response.MAC, response.signature(key, request.Nonce))
	}
}

// The hub refuses an enrollment with one sentence under "detail". Reading the
// hub's own example rather than a string invented here means a change to that
// shape shows up as a failing test instead of as an operator staring at raw
// JSON on a router.
func TestTheErrorFixtureBecomesOneSentence(t *testing.T) {
	sentence := problem(contract.ErrorFixture())
	if sentence == "" {
		t.Fatal("the error fixture produced no sentence")
	}
	if strings.Contains(sentence, "{") || strings.Contains(sentence, "detail") {
		t.Errorf("the hub's refusal came out as raw JSON: %s", sentence)
	}
	var fixture map[string]any
	if err := json.Unmarshal(contract.ErrorFixture(), &fixture); err != nil {
		t.Fatalf("parsing error.json: %v", err)
	}
	if len(fixture) != 1 {
		t.Errorf("error.json has %d fields, the contract says one: %v", len(fixture), fixture)
	}
	if _, present := fixture["detail"]; !present {
		t.Error("error.json has no detail field")
	}
}
