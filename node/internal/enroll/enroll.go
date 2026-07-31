// Package enroll speaks the hub's enrollment endpoint.
//
// This is a contract between two languages: the hub answers in Python and this
// parses in Go, and nothing catches a mismatch at compile time. The field names
// and types here are fixed by the fixtures in contracts/enrollment, which both
// test suites load, rather than by either side's convenience.
package enroll

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"

	"shadow9-node/internal/wgkey"
)

const (
	// Path is where the hub answers, under the API prefix.
	Path = "/api/wireguard/enroll"
	// RefreshPath is where an enrolled node pulls current settings.
	RefreshPath = "/api/wireguard/refresh"
	// Protocol is the enrollment protocol major version this client understands.
	Protocol          = 1
	joinMACMessage    = "shadow9-join-mac-v1"
	refreshMACMessage = "shadow9-refresh-v1"
)

// Request is what a node sends to join the tunnel.
type Request struct {
	TokenID   string   `json:"token_id"`
	Name      string   `json:"name"`
	PublicKey string   `json:"public_key"`
	Routes    []string `json:"routes"`
	Nonce     string   `json:"nonce"`
	MAC       string   `json:"mac"`
}

// Response is what the hub answers a node that joined.
//
// A node needs the address it was given, the hub connection details and the
// tunnel settings. No private key ever appears here: the node generates its
// own keypair and sends only the public half.
type Response struct {
	Address       string `json:"address"`
	HubPublicKey  string `json:"hub_public_key"`
	HubEndpoint   string `json:"hub_endpoint"`
	TunnelNetwork string `json:"tunnel_network"`
	MTU           *int   `json:"mtu"`
	Keepalive     *int   `json:"keepalive"`
	Protocol      *int   `json:"protocol"`
	MAC           string `json:"mac"`
}

// RefreshRequest is what an enrolled node sends to pull current settings.
type RefreshRequest struct {
	Name  string `json:"name"`
	Nonce string `json:"nonce"`
	MAC   string `json:"mac"`
}

// RefreshResponse is the complete tunnel state the hub returns to one node.
type RefreshResponse struct {
	Address       string   `json:"address"`
	HubPublicKey  string   `json:"hub_public_key"`
	HubEndpoint   string   `json:"hub_endpoint"`
	TunnelNetwork string   `json:"tunnel_network"`
	AllowedIPs    []string `json:"allowed_ips"`
	MTU           *int     `json:"mtu"`
	Keepalive     *int     `json:"keepalive"`
	Protocol      *int     `json:"protocol"`
	Revision      *int     `json:"revision"`
	MAC           string   `json:"mac"`
}

// RefreshKey is the derived credential kept by an enrolled node.
type RefreshKey [sha256.Size]byte

// ParseRefreshKey reads the lowercase hexadecimal form saved in UCI.
func ParseRefreshKey(text string) (RefreshKey, error) {
	var key RefreshKey
	raw, err := hex.DecodeString(strings.TrimSpace(text))
	if err != nil || len(raw) != len(key) {
		return key, errors.New("the saved refresh key is unusable")
	}
	copy(key[:], raw)
	return key, nil
}

// String returns the lowercase hexadecimal form stored in UCI.
func (k RefreshKey) String() string { return hex.EncodeToString(k[:]) }

// ErrHubKeyMismatch is returned when the hub's public key is not the one the
// token names.
//
// The response MAC is checked first. This independent comparison keeps a node
// from building a tunnel with a different hub key if the two ever disagree.
var ErrHubKeyMismatch = errors.New("the hub's public key is not the one the join token names")

// Token is a join token, "<id>.<secret>.<hub public key>".
type Token struct {
	// ID is the public lookup value sent in the request.
	ID string
	// HubKey is the hub public key the token commits to.
	HubKey wgkey.Key
	macKey []byte
}

// ParseToken splits a join token and checks that its key half is a key.
//
// All three alphabets exclude dots, so an extra or missing separator is a
// malformed token rather than an ambiguous split.
func ParseToken(text string) (Token, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return Token{}, errors.New("the join token is empty")
	}
	parts := strings.Split(text, ".")
	if len(parts) != 3 {
		return Token{}, errors.New(
			"the join token should look like <id>.<secret>.<hub public key>")
	}
	tokenID, secret, hubKey := parts[0], parts[1], parts[2]
	if tokenID == "" {
		return Token{}, errors.New("the join token has no id")
	}
	if secret == "" {
		return Token{}, errors.New("the join token has no secret half")
	}
	key, err := wgkey.Parse(hubKey)
	if err != nil {
		return Token{}, fmt.Errorf("the hub key half of the join token is unusable: %w", err)
	}
	digest := hmac.New(sha256.New, []byte(secret))
	_, _ = digest.Write([]byte(joinMACMessage))
	return Token{ID: tokenID, HubKey: key, macKey: digest.Sum(nil)}, nil
}

// RefreshKey derives the durable refresh credential from the join MAC key.
func (t Token) RefreshKey() RefreshKey {
	digest := hmac.New(sha256.New, t.macKey)
	_, _ = digest.Write([]byte(refreshMACMessage))
	var key RefreshKey
	copy(key[:], digest.Sum(nil))
	return key
}

func newNonce() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating the enrollment nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (r Request) signature(key []byte) string {
	message := "shadow9-join-request-v1\n" +
		"token_id=" + r.TokenID + "\n" +
		"name=" + r.Name + "\n" +
		"public_key=" + r.PublicKey + "\n" +
		"routes=" + strings.Join(r.Routes, ",") + "\n" +
		"nonce=" + r.Nonce + "\n"
	digest := hmac.New(sha256.New, key)
	_, _ = digest.Write([]byte(message))
	return hex.EncodeToString(digest.Sum(nil))
}

func (r Response) signature(key []byte, nonce string) string {
	message := "shadow9-join-response-v1\n" +
		"nonce=" + nonce + "\n" +
		"address=" + r.Address + "\n" +
		"hub_public_key=" + r.HubPublicKey + "\n" +
		"hub_endpoint=" + r.HubEndpoint + "\n" +
		"tunnel_network=" + r.TunnelNetwork + "\n" +
		fmt.Sprintf("mtu=%d\nkeepalive=%d\nprotocol=%d\n", *r.MTU, *r.Keepalive, *r.Protocol)
	digest := hmac.New(sha256.New, key)
	_, _ = digest.Write([]byte(message))
	return hex.EncodeToString(digest.Sum(nil))
}

func (r RefreshRequest) signature(key RefreshKey) string {
	message := "shadow9-refresh-request-v1\n" +
		"name=" + r.Name + "\n" +
		"nonce=" + r.Nonce + "\n"
	digest := hmac.New(sha256.New, key[:])
	_, _ = digest.Write([]byte(message))
	return hex.EncodeToString(digest.Sum(nil))
}

func (r RefreshResponse) signature(key RefreshKey, nonce string) string {
	message := "shadow9-refresh-response-v1\n" +
		"nonce=" + nonce + "\n" +
		"address=" + r.Address + "\n" +
		"hub_public_key=" + r.HubPublicKey + "\n" +
		"hub_endpoint=" + r.HubEndpoint + "\n" +
		"tunnel_network=" + r.TunnelNetwork + "\n" +
		"allowed_ips=" + strings.Join(r.AllowedIPs, ",") + "\n" +
		fmt.Sprintf("mtu=%d\nkeepalive=%d\nprotocol=%d\nrevision=%d\n",
			*r.MTU, *r.Keepalive, *r.Protocol, *r.Revision)
	digest := hmac.New(sha256.New, key[:])
	_, _ = digest.Write([]byte(message))
	return hex.EncodeToString(digest.Sum(nil))
}

// Client calls one hub.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// Enroll sends the request and returns the hub's answer, having already
// checked that the answer came from the hub the token names.
//
// The check is here rather than at the call site on purpose: a caller cannot
// obtain a Response that was not verified, so there is no path where config
// gets written against an unverified hub.
func (c Client) Enroll(ctx context.Context, token Token, name, publicKey string, routes []string) (Response, error) {
	var answer Response

	if routes == nil {
		// The hub's model is a list with a default of empty. A JSON null is
		// not a list and would come back as a 422.
		routes = []string{}
	}
	nonce, err := newNonce()
	if err != nil {
		return answer, err
	}
	sent := Request{
		TokenID:   token.ID,
		Name:      name,
		PublicKey: publicKey,
		Routes:    routes,
		Nonce:     nonce,
	}
	sent.MAC = sent.signature(token.macKey)
	body, err := json.Marshal(sent)
	if err != nil {
		return answer, fmt.Errorf("encoding the enrollment request: %w", err)
	}

	endpoint := strings.TrimSuffix(c.BaseURL, "/") + Path
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return answer, fmt.Errorf("building the request to %s: %w", endpoint, err)
	}
	request.Header.Set("Content-Type", "application/json")

	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return answer, fmt.Errorf("enrolling with %s: %w", endpoint, err)
	}
	defer response.Body.Close()

	// Bounded, because an unauthenticated endpoint over plain HTTP is exactly
	// where an unbounded read is a way to exhaust a router's memory.
	const mostBodyWorthReading = 1 << 20
	raw, err := io.ReadAll(io.LimitReader(response.Body, mostBodyWorthReading))
	if err != nil {
		return answer, fmt.Errorf("reading the hub's answer: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		return answer, fmt.Errorf("the hub refused the enrollment with HTTP %d: %s",
			response.StatusCode, problem(raw))
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&answer); err != nil {
		return answer, fmt.Errorf("the hub's answer does not match the enrollment contract: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Response{}, fmt.Errorf("the hub's answer has trailing JSON after the enrollment object")
	}
	if err := answer.check(); err != nil {
		return Response{}, err
	}
	if err := answer.verify(token, nonce); err != nil {
		return Response{}, err
	}
	return answer, nil
}

// Refresh pulls and verifies the complete current settings for an enrolled node.
func (c Client) Refresh(ctx context.Context, key RefreshKey, name string) (RefreshResponse, error) {
	var answer RefreshResponse
	nonce, err := newNonce()
	if err != nil {
		return answer, err
	}
	sent := RefreshRequest{Name: name, Nonce: nonce}
	sent.MAC = sent.signature(key)
	body, err := json.Marshal(sent)
	if err != nil {
		return answer, fmt.Errorf("encoding the refresh request: %w", err)
	}

	endpoint := strings.TrimSuffix(c.BaseURL, "/") + RefreshPath
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return answer, fmt.Errorf("building the request to %s: %w", endpoint, err)
	}
	request.Header.Set("Content-Type", "application/json")
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return answer, fmt.Errorf("refreshing with %s: %w", endpoint, err)
	}
	defer response.Body.Close()

	const mostBodyWorthReading = 1 << 20
	raw, err := io.ReadAll(io.LimitReader(response.Body, mostBodyWorthReading))
	if err != nil {
		return answer, fmt.Errorf("reading the hub's answer: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return answer, fmt.Errorf("the hub refused the refresh with HTTP %d: %s",
			response.StatusCode, problem(raw))
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&answer); err != nil {
		return answer, fmt.Errorf("the hub's answer does not match the refresh contract: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return RefreshResponse{}, errors.New("the hub's answer has trailing JSON after the refresh object")
	}
	if err := answer.check(); err != nil {
		return RefreshResponse{}, err
	}
	if err := answer.verify(key, nonce); err != nil {
		return RefreshResponse{}, err
	}
	return answer, nil
}

// check reports a field the hub left empty, before anything is written.
func (r Response) check() error {
	for _, field := range []struct{ name, value string }{
		{"address", r.Address},
		{"hub_public_key", r.HubPublicKey},
		{"hub_endpoint", r.HubEndpoint},
		{"tunnel_network", r.TunnelNetwork},
		{"mac", r.MAC},
	} {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("the hub's answer has no %s", field.name)
		}
	}
	for _, field := range []struct {
		name  string
		value *int
	}{
		{"mtu", r.MTU},
		{"keepalive", r.Keepalive},
		{"protocol", r.Protocol},
	} {
		if field.value == nil {
			return fmt.Errorf("the hub's answer has no %s", field.name)
		}
	}
	if *r.MTU <= 0 {
		return fmt.Errorf("the hub's mtu must be positive, not %d", *r.MTU)
	}
	if *r.Keepalive < 0 {
		return fmt.Errorf("the hub's keepalive cannot be negative: %d", *r.Keepalive)
	}
	if *r.Protocol != Protocol {
		return fmt.Errorf("the hub uses enrollment protocol %d, but this node understands protocol %d",
			*r.Protocol, Protocol)
	}
	network, err := netip.ParsePrefix(strings.TrimSpace(r.TunnelNetwork))
	if err != nil {
		return fmt.Errorf("the hub's tunnel_network %q is not a CIDR: %w", r.TunnelNetwork, err)
	}
	addressText := strings.TrimSpace(r.Address)
	var address netip.Addr
	if strings.Contains(addressText, "/") {
		assigned, err := netip.ParsePrefix(addressText)
		if err != nil {
			return fmt.Errorf("the hub's address %q is unusable: %w", r.Address, err)
		}
		address = assigned.Addr()
	} else {
		address, err = netip.ParseAddr(addressText)
		if err != nil {
			return fmt.Errorf("the hub's address %q is unusable: %w", r.Address, err)
		}
	}
	if address.Is4() != network.Addr().Is4() {
		return fmt.Errorf("the hub's address %s and tunnel_network %s use different address families",
			r.Address, r.TunnelNetwork)
	}
	if !network.Contains(address) {
		return fmt.Errorf("the hub's address %s is not inside tunnel_network %s",
			r.Address, r.TunnelNetwork)
	}
	return nil
}

func (r RefreshResponse) check() error {
	base := Response{
		Address: r.Address, HubPublicKey: r.HubPublicKey, HubEndpoint: r.HubEndpoint,
		TunnelNetwork: r.TunnelNetwork, MTU: r.MTU, Keepalive: r.Keepalive,
		Protocol: r.Protocol, MAC: r.MAC,
	}
	if err := base.check(); err != nil {
		return err
	}
	if r.AllowedIPs == nil {
		return errors.New("the hub's answer has no allowed_ips")
	}
	if len(r.AllowedIPs) == 0 {
		return errors.New("the hub's allowed_ips is empty")
	}
	for _, text := range r.AllowedIPs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(text))
		if err != nil || prefix.String() != strings.TrimSpace(text) {
			return fmt.Errorf("the hub's allowed_ips contains an unusable network %q", text)
		}
	}
	if r.Revision == nil {
		return errors.New("the hub's answer has no revision")
	}
	if *r.Revision < 0 {
		return fmt.Errorf("the hub's revision cannot be negative: %d", *r.Revision)
	}
	return nil
}

// verify compares the hub's key with the one the token names.
//
// The comparison is on the decoded 32 bytes rather than on the two strings, so
// a difference in base64 padding or surrounding whitespace is not mistaken for
// a different hub.
func (r Response) verify(token Token, nonce string) error {
	provided, err := hex.DecodeString(r.MAC)
	if err != nil {
		return fmt.Errorf("the hub's answer has an invalid MAC")
	}
	expected, err := hex.DecodeString(r.signature(token.macKey, nonce))
	if err != nil {
		return fmt.Errorf("checking the hub's answer MAC: %w", err)
	}
	if !hmac.Equal(provided, expected) {
		return fmt.Errorf("the hub's answer has an invalid MAC")
	}
	key, err := wgkey.Parse(strings.TrimSpace(r.HubPublicKey))
	if err != nil {
		return fmt.Errorf("the hub's public key is unusable: %w", err)
	}
	if key != token.HubKey {
		return fmt.Errorf("%w: the token names %s and the hub answered with %s",
			ErrHubKeyMismatch, token.HubKey, key)
	}
	return nil
}

func (r RefreshResponse) verify(key RefreshKey, nonce string) error {
	provided, err := hex.DecodeString(r.MAC)
	if err != nil {
		return errors.New("the hub's answer has an invalid MAC")
	}
	expected, err := hex.DecodeString(r.signature(key, nonce))
	if err != nil {
		return fmt.Errorf("checking the hub's answer MAC: %w", err)
	}
	if !hmac.Equal(provided, expected) {
		return errors.New("the hub's answer has an invalid MAC")
	}
	return nil
}

// problem turns the hub's error body into one sentence.
//
// The hub answers a rejected enrollment with a sentence under "detail", and
// pydantic answers a malformed body with a list under the same name. Both are
// handled, because a client that prints the raw JSON of one of them tells the
// operator nothing.
func problem(raw []byte) string {
	var sentence struct {
		Detail string `json:"detail"`
	}
	if json.Unmarshal(raw, &sentence) == nil && sentence.Detail != "" {
		return sentence.Detail
	}
	var fields struct {
		Detail []struct {
			Location []any  `json:"loc"`
			Message  string `json:"msg"`
		} `json:"detail"`
	}
	if json.Unmarshal(raw, &fields) == nil && len(fields.Detail) > 0 {
		reported := make([]string, 0, len(fields.Detail))
		for _, f := range fields.Detail {
			where := ""
			if len(f.Location) > 0 {
				where = fmt.Sprintf("%v: ", f.Location[len(f.Location)-1])
			}
			reported = append(reported, where+f.Message)
		}
		return strings.Join(reported, "; ")
	}
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return "the hub said nothing about why"
	}
	const mostWorthQuoting = 200
	if len(text) > mostWorthQuoting {
		text = text[:mostWorthQuoting] + "..."
	}
	return text
}
