package enroll

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"shadow9-node/internal/contract"
)

const (
	hubPublicKey    = "hR3n0oPxK9zLm2vQwE4tYuIoP1aSdF6gH8jKlZxCvB0="
	anotherHubKey   = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="
	goodToken       = "join-token-id-value.s3cr3t-join-token-value." + hubPublicKey
	tokenForAnother = "join-token-id-value.s3cr3t-join-token-value." + anotherHubKey
)

func decodeStrict(raw []byte, into any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(into)
}

// hubAnswering serves one canned answer and records what it was sent.
func hubAnswering(t *testing.T, status int, body string) (*httptest.Server, *Request) {
	t.Helper()
	received := &Request{}
	signingToken, err := ParseToken(goodToken)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != Path {
			t.Errorf("the client posted to %s, want %s", r.URL.Path, Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("the client used %s, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type was %q", got)
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, received); err != nil {
			t.Errorf("the request body is not the contract's shape: %v", err)
		}
		var fields map[string]any
		var answer Response
		if json.Unmarshal([]byte(body), &fields) == nil {
			if _, signed := fields["mac"]; signed && json.Unmarshal([]byte(body), &answer) == nil &&
				answer.MTU != nil && answer.Keepalive != nil && answer.Protocol != nil {
				answer.MAC = answer.signature(signingToken.macKey, received.Nonce)
				raw, marshalErr := json.Marshal(answer)
				if marshalErr != nil {
					t.Errorf("signing the response: %v", marshalErr)
				} else {
					body = string(raw)
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	return server, received
}

func enrollWith(t *testing.T, server *httptest.Server, token string) (Response, error) {
	t.Helper()
	parsed, err := ParseToken(token)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	client := Client{BaseURL: server.URL, HTTP: server.Client()}
	return client.Enroll(context.Background(), parsed, "branch-gateway",
		"hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=", []string{"192.168.1.0/24"})
}

type changedAnswer struct {
	field string
}

type refreshAnswer struct {
	change string
	sent   *RefreshRequest
}

func (h refreshAnswer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != RefreshPath {
		http.Error(w, "wrong path", http.StatusNotFound)
		return
	}
	if err := json.NewDecoder(r.Body).Decode(h.sent); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	mtu, keepalive, protocol, revision := 1412, 20, Protocol, 7
	answer := RefreshResponse{
		Address: "10.9.0.7", HubPublicKey: hubPublicKey,
		HubEndpoint: "203.0.113.10:51820", TunnelNetwork: "10.9.0.0/24",
		AllowedIPs: []string{"10.9.0.0/24", "192.168.2.0/24"},
		MTU:        &mtu, Keepalive: &keepalive, Protocol: &protocol, Revision: &revision,
	}
	token, err := ParseToken(goodToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	key := token.RefreshKey()
	answer.MAC = answer.signature(key, h.sent.Nonce)
	switch h.change {
	case "allowed_ips":
		answer.AllowedIPs = []string{"10.9.0.0/24", "192.168.9.0/24"}
	case "revision":
		changed := revision + 1
		answer.Revision = &changed
	}
	_ = json.NewEncoder(w).Encode(answer)
}

func (h changedAnswer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var request Request
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	mtu, keepalive, protocol := 1412, 20, Protocol
	answer := Response{
		Address:       "10.9.0.7",
		HubPublicKey:  hubPublicKey,
		HubEndpoint:   "203.0.113.10:51820",
		TunnelNetwork: "10.9.0.0/24",
		MTU:           &mtu,
		Keepalive:     &keepalive,
		Protocol:      &protocol,
	}
	token, err := ParseToken(goodToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	signedNonce := request.Nonce
	if h.field == "nonce" {
		signedNonce = "nonce-from-another-request"
	}
	answer.MAC = answer.signature(token.macKey, signedNonce)
	switch h.field {
	case "address":
		answer.Address = "10.9.0.8"
	case "hub_endpoint":
		answer.HubEndpoint = "198.51.100.20:51820"
	case "tunnel_network":
		answer.TunnelNetwork = "10.9.0.0/25"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(answer)
}

func TestParseTokenSplitsTheSecretFromTheHubKey(t *testing.T) {
	token, err := ParseToken("  " + goodToken + "\n")
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	if token.ID != "join-token-id-value" {
		t.Errorf("the token id is %q", token.ID)
	}
	if token.HubKey.String() != hubPublicKey {
		t.Errorf("the hub key came out as %s", token.HubKey)
	}
}

func TestRefreshKeyIsDerivedFromTheJoinMACKey(t *testing.T) {
	token, err := ParseToken(goodToken)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	if got, want := token.RefreshKey().String(), "b92a5ead82224c3e5f1ad5905d4027d441348999e6e5999923438f5ce8237ff0"; got != want {
		t.Errorf("the refresh key is %s, want %s", got, want)
	}
}

// A token with extra dots is malformed. Both sides must call it malformed
// rather than quietly finding three usable-looking parts inside it.
func TestParseTokenSplitsOnTheFirstSeparatorLikeTheHub(t *testing.T) {
	_, err := ParseToken("a.secret.with.dots." + hubPublicKey)
	if err == nil {
		t.Fatal("a token with extra dots parsed, but the hub reads its key half as " +
			"\"secret.with.dots." + hubPublicKey + "\" and rejects it")
	}
	if !strings.Contains(err.Error(), "should look like") {
		t.Errorf("the error was %q, want it to name the token shape", err)
	}
}

func TestParseTokenRejectsWhatCannotBeChecked(t *testing.T) {
	for _, tc := range []struct{ name, token, says string }{
		{"empty", "", "empty"},
		{"blank", "   ", "empty"},
		{"no key half", "just-a-secret", "should look like"},
		{"no id", ".secret." + hubPublicKey, "no id"},
		{"no secret half", "id.." + hubPublicKey, "no secret half"},
		{"key half is not a key", "id.secret.not-a-key", "unusable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseToken(tc.token)
			if err == nil {
				t.Fatal("ParseToken accepted it")
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("the error was %q, which does not say %q", err, tc.says)
			}
		})
	}
}

func TestEnrollReturnsTheHubsAnswer(t *testing.T) {
	server, sent := hubAnswering(t, http.StatusOK, `{
		"address": "10.9.0.7",
		"hub_public_key": "`+hubPublicKey+`",
		"hub_endpoint": "203.0.113.10:51820",
		"tunnel_network": "10.9.0.0/24",
		"mtu": 1412,
		"keepalive": 20,
		"protocol": 1,
		"mac": "sign"
	}`)
	answer, err := enrollWith(t, server, goodToken)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if answer.Address != "10.9.0.7" || answer.HubEndpoint != "203.0.113.10:51820" {
		t.Errorf("the answer came back as %+v", answer)
	}
	if answer.MTU == nil || *answer.MTU != 1412 || answer.Keepalive == nil || *answer.Keepalive != 20 {
		t.Errorf("the tunnel settings came back as %+v", answer)
	}
	if sent.TokenID != "join-token-id-value" {
		t.Errorf("the client sent the token id as %q", sent.TokenID)
	}
	if sent.Name != "branch-gateway" {
		t.Errorf("the client sent the name as %q", sent.Name)
	}
	if len(sent.Routes) != 1 || sent.Routes[0] != "192.168.1.0/24" {
		t.Errorf("the client sent the routes as %v", sent.Routes)
	}
	if sent.Nonce == "" || sent.MAC == "" {
		t.Errorf("the signed request is incomplete: %+v", sent)
	}
	raw, _ := json.Marshal(sent)
	if strings.Contains(string(raw), "s3cr3t-join-token-value") {
		t.Errorf("the serialized request exposed the token secret: %s", raw)
	}
}

func TestEnrollRefusesChangedRoutingFieldsBeforeTheyCanReachTheRouter(t *testing.T) {
	for _, field := range []string{"address", "hub_endpoint", "tunnel_network"} {
		t.Run(field, func(t *testing.T) {
			server := httptest.NewServer(changedAnswer{field: field})
			t.Cleanup(server.Close)

			answer, err := enrollWith(t, server, goodToken)

			if err == nil || !strings.Contains(err.Error(), "invalid MAC") {
				t.Fatalf("Enroll accepted the changed %s: %v", field, err)
			}
			if answer != (Response{}) {
				t.Errorf("a response that the router could write escaped verification: %+v", answer)
			}
		})
	}
}

func TestEnrollRefusesAResponseSignedForAnotherRequestsNonce(t *testing.T) {
	server := httptest.NewServer(changedAnswer{field: "nonce"})
	t.Cleanup(server.Close)

	answer, err := enrollWith(t, server, goodToken)

	if err == nil || !strings.Contains(err.Error(), "invalid MAC") {
		t.Fatalf("Enroll accepted a replayed response: %v", err)
	}
	if answer != (Response{}) {
		t.Errorf("a replayed response escaped verification: %+v", answer)
	}
}

// The MAC is checked first, and this independent key comparison must also keep
// an answer from escaping Enroll when it fails.
func TestEnrollRefusesAHubWhoseKeyIsNotTheOneTheTokenNames(t *testing.T) {
	server, _ := hubAnswering(t, http.StatusOK, `{
		"address": "10.9.0.7",
		"hub_public_key": "`+hubPublicKey+`",
		"hub_endpoint": "203.0.113.10:51820",
		"tunnel_network": "10.9.0.0/24",
		"mtu": 1412,
		"keepalive": 20,
		"protocol": 1,
		"mac": "sign"
	}`)
	answer, err := enrollWith(t, server, tokenForAnother)
	if err == nil {
		t.Fatal("Enroll accepted a hub the token does not name")
	}
	if !errors.Is(err, ErrHubKeyMismatch) {
		t.Errorf("the error is not ErrHubKeyMismatch: %v", err)
	}
	if answer != (Response{}) {
		t.Errorf("a usable answer came back alongside the mismatch: %+v", answer)
	}
}

// Base64 has one representation of these bytes, but a hub that pads or trims
// differently, or leaves a newline on, is still the same hub. Comparing the
// decoded bytes rather than the two strings keeps that from reading as an
// attack.
func TestEnrollAcceptsTheSameKeyWithSurroundingWhitespace(t *testing.T) {
	server, _ := hubAnswering(t, http.StatusOK, `{
		"address": "10.9.0.7",
		"hub_public_key": " `+hubPublicKey+` ",
		"hub_endpoint": "203.0.113.10:51820",
		"tunnel_network": "10.9.0.0/24",
		"mtu": 1412,
		"keepalive": 20,
		"protocol": 1,
		"mac": "sign"
	}`)
	if _, err := enrollWith(t, server, goodToken); err != nil {
		t.Errorf("Enroll rejected the right hub over whitespace: %v", err)
	}
}

func TestEnrollRejectsAnAnswerWithAFieldMissing(t *testing.T) {
	for _, missing := range []string{
		"address", "hub_public_key", "hub_endpoint", "tunnel_network", "mtu", "keepalive", "protocol", "mac",
	} {
		t.Run(missing, func(t *testing.T) {
			body := map[string]any{
				"address":        "10.9.0.7",
				"hub_public_key": hubPublicKey,
				"hub_endpoint":   "203.0.113.10:51820",
				"tunnel_network": "10.9.0.0/24",
				"mtu":            1412,
				"keepalive":      20,
				"protocol":       Protocol,
				"mac":            "sign",
			}
			delete(body, missing)
			raw, _ := json.Marshal(body)
			server, _ := hubAnswering(t, http.StatusOK, string(raw))
			_, err := enrollWith(t, server, goodToken)
			if err == nil {
				t.Fatalf("Enroll accepted an answer with no %s", missing)
			}
			if !strings.Contains(err.Error(), missing) {
				t.Errorf("the error does not name %s: %v", missing, err)
			}
		})
	}
}

func TestEnrollIgnoresUnknownFields(t *testing.T) {
	server, _ := hubAnswering(t, http.StatusOK, `{
		"address": "10.9.0.7",
		"hub_public_key": "`+hubPublicKey+`",
		"hub_endpoint": "203.0.113.10:51820",
		"tunnel_network": "10.9.0.0/24",
		"mtu": 1412,
		"keepalive": 20,
		"protocol": 1,
		"mac": "sign",
		"allowed_ips": ["10.9.0.0/24", "192.168.50.0/24"]
	}`)
	if _, err := enrollWith(t, server, goodToken); err != nil {
		t.Fatalf("Enroll rejected an optional field it does not need: %v", err)
	}
}

func TestEnrollRejectsARequiredFieldWithTheWrongType(t *testing.T) {
	server, _ := hubAnswering(t, http.StatusOK, `{
		"address": "10.9.0.7",
		"hub_public_key": "`+hubPublicKey+`",
		"hub_endpoint": "203.0.113.10:51820",
		"tunnel_network": "10.9.0.0/24",
		"mtu": "1412",
		"keepalive": 20,
		"protocol": 1,
		"mac": "sign"
	}`)
	_, err := enrollWith(t, server, goodToken)
	if err == nil || !strings.Contains(err.Error(), "mtu") {
		t.Fatalf("Enroll did not name the mistyped mtu: %v", err)
	}
}

func TestEnrollRejectsAnUnknownProtocolMajor(t *testing.T) {
	server, _ := hubAnswering(t, http.StatusOK, `{
		"address": "10.9.0.7",
		"hub_public_key": "`+hubPublicKey+`",
		"hub_endpoint": "203.0.113.10:51820",
		"tunnel_network": "10.9.0.0/24",
		"mtu": 1412,
		"keepalive": 20,
		"protocol": 2,
		"mac": "sign"
	}`)
	_, err := enrollWith(t, server, goodToken)
	if err == nil || !strings.Contains(err.Error(), "protocol 2") {
		t.Fatalf("Enroll did not refuse protocol 2: %v", err)
	}
}

func TestEnrollRejectsAnUnusableTunnelNetwork(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address string
		network string
		says    string
	}{
		{"not a CIDR", "10.9.0.7", "not-a-cidr", "not a CIDR"},
		{"address outside network", "10.10.0.7", "10.9.0.0/24", "not inside"},
		{"mixed address families", "2001:db8::7", "10.9.0.0/24", "different address families"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := hubAnswering(t, http.StatusOK, `{
				"address": "`+tc.address+`",
				"hub_public_key": "`+hubPublicKey+`",
				"hub_endpoint": "203.0.113.10:51820",
				"tunnel_network": "`+tc.network+`",
				"mtu": 1412,
				"keepalive": 20,
				"protocol": 1,
				"mac": "sign"
			}`)
			_, err := enrollWith(t, server, goodToken)
			if err == nil {
				t.Fatal("Enroll accepted the answer")
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("the error does not say %q: %v", tc.says, err)
			}
		})
	}
}

func TestEnrollRejectsJsonAfterTheAnswer(t *testing.T) {
	server, _ := hubAnswering(t, http.StatusOK, `{
		"address": "10.9.0.7",
		"hub_public_key": "`+hubPublicKey+`",
		"hub_endpoint": "203.0.113.10:51820",
		"tunnel_network": "10.9.0.0/24",
		"mtu": 1412,
		"keepalive": 20,
		"protocol": 1,
		"mac": "sign"
	} {"address":"10.9.0.8"}`)

	_, err := enrollWith(t, server, goodToken)
	if err == nil {
		t.Fatal("Enroll accepted a second JSON object")
	}
	if !strings.Contains(err.Error(), "trailing JSON") {
		t.Errorf("the error does not name the extra JSON: %v", err)
	}
}

// The hub answers a rejected enrollment with one sentence under "detail". A
// client that prints raw JSON at the operator tells them nothing.
func TestEnrollReportsTheHubsOwnSentence(t *testing.T) {
	server, _ := hubAnswering(t, http.StatusUnauthorized,
		`{"detail":"That join token has already been spent."}`)
	_, err := enrollWith(t, server, goodToken)
	if err == nil {
		t.Fatal("Enroll accepted a 401")
	}
	if !strings.Contains(err.Error(), "already been spent") {
		t.Errorf("the error does not carry the hub's sentence: %v", err)
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("the error does not carry the status: %v", err)
	}
}

// pydantic answers a malformed body with a list under the same name, so the
// client has two error shapes to handle and not one per field.
func TestEnrollReadsPydanticsFieldByFieldAnswer(t *testing.T) {
	server, _ := hubAnswering(t, http.StatusUnprocessableEntity, `{"detail":[
		{"loc":["body","name"],"msg":"Field required","type":"missing"}
	]}`)
	_, err := enrollWith(t, server, goodToken)
	if err == nil {
		t.Fatal("Enroll accepted a 422")
	}
	if !strings.Contains(err.Error(), "name: Field required") {
		t.Errorf("the error does not say which field: %v", err)
	}
}

func TestEnrollSurvivesAnErrorBodyThatIsNotJson(t *testing.T) {
	server, _ := hubAnswering(t, http.StatusBadGateway, "<html>502 Bad Gateway</html>")
	_, err := enrollWith(t, server, goodToken)
	if err == nil {
		t.Fatal("Enroll accepted a 502")
	}
	if !strings.Contains(err.Error(), "502") {
		t.Errorf("the error does not carry the status: %v", err)
	}
}

func TestEnrollNamesTheHubWhenItCannotBeReached(t *testing.T) {
	client := Client{BaseURL: "http://127.0.0.1:1"}
	token, err := ParseToken(goodToken)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	_, err = client.Enroll(context.Background(), token, "n", "k", nil)
	if err == nil {
		t.Fatal("Enroll succeeded against a closed port")
	}
	if !strings.Contains(err.Error(), Path) {
		t.Errorf("the error does not say where it was going: %v", err)
	}
}

// The fixtures are a matched pair: the token in request.json names the hub key
// in response.json, so the happy path runs end to end on the contract's own
// example rather than on values invented in a test.
func TestTheFixturePairEnrollsCleanly(t *testing.T) {
	var fixtureRequest Request
	if err := decodeStrict(contract.RequestFixture(), &fixtureRequest); err != nil {
		t.Fatalf("decoding request.json: %v", err)
	}
	server, sent := hubAnswering(t, http.StatusOK, string(contract.ResponseFixture()))

	var fixtureResponse Response
	if err := decodeStrict(contract.ResponseFixture(), &fixtureResponse); err != nil {
		t.Fatalf("decoding response.json: %v", err)
	}
	token, err := ParseToken(
		fixtureRequest.TokenID + "." + manifest(t).ExampleSecret + "." + fixtureResponse.HubPublicKey,
	)
	if err != nil {
		t.Fatalf("building the token for the fixture request: %v", err)
	}
	client := Client{BaseURL: server.URL, HTTP: server.Client()}
	answer, err := client.Enroll(context.Background(), token,
		fixtureRequest.Name, fixtureRequest.PublicKey, fixtureRequest.Routes)
	if err != nil {
		t.Fatalf("the fixture pair did not enroll: %v", err)
	}
	if answer.HubPublicKey != token.HubKey.String() {
		t.Error("the fixtures are not a matched pair, so the hub key check proves nothing here")
	}
	if sent.Name != fixtureRequest.Name || sent.PublicKey != fixtureRequest.PublicKey {
		t.Errorf("the client did not send what the fixture describes: %+v", sent)
	}
}

func TestRefreshReturnsCompleteVerifiedSettings(t *testing.T) {
	token, err := ParseToken(goodToken)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	sent := &RefreshRequest{}
	server := httptest.NewServer(refreshAnswer{sent: sent})
	t.Cleanup(server.Close)
	client := Client{BaseURL: server.URL, HTTP: server.Client()}
	answer, err := client.Refresh(context.Background(), token.RefreshKey(), "branch-gateway")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if sent.Name != "branch-gateway" || sent.Nonce == "" || sent.MAC == "" {
		t.Errorf("the refresh request is incomplete: %+v", sent)
	}
	if got := strings.Join(answer.AllowedIPs, ","); got != "10.9.0.0/24,192.168.2.0/24" {
		t.Errorf("allowed IPs are %s", got)
	}
	if answer.Revision == nil || *answer.Revision != 7 {
		t.Errorf("revision is %v", answer.Revision)
	}
}

func TestRefreshRefusesChangedSignedFields(t *testing.T) {
	token, err := ParseToken(goodToken)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	for _, field := range []string{"allowed_ips", "revision"} {
		t.Run(field, func(t *testing.T) {
			server := httptest.NewServer(refreshAnswer{change: field, sent: &RefreshRequest{}})
			t.Cleanup(server.Close)
			client := Client{BaseURL: server.URL, HTTP: server.Client()}
			answer, err := client.Refresh(context.Background(), token.RefreshKey(), "branch-gateway")
			if err == nil || !strings.Contains(err.Error(), "invalid MAC") {
				t.Fatalf("Refresh accepted changed %s: %+v, %v", field, answer, err)
			}
			if answer.Address != "" || answer.AllowedIPs != nil {
				t.Errorf("an unverified answer escaped: %+v", answer)
			}
		})
	}
}
