package tunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Authorization struct {
	UserID   string `json:"userId"`
	TunnelID string `json:"tunnelId"`
	Port     int    `json:"remotePort"`
}
type Authorizer interface {
	Authorize(context.Context, string, string, int) (Authorization, error)
}

// HTTPAuthorizer delegates identity and port ownership to an operator endpoint.
type HTTPAuthorizer struct {
	hook, secret string
	client       *http.Client
}

func NewHTTPAuthorizer(hook, secret string) (*HTTPAuthorizer, error) {
	u, err := url.Parse(hook)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"))) {
		return nil, errors.New("authorization endpoint must use HTTPS (loopback HTTP is allowed)")
	}
	if strings.ContainsAny(secret, "\r\n\x00") {
		return nil, errors.New("invalid authorization credential")
	}
	if len(secret) < 32 {
		return nil, errors.New("private authorization hook requires an operator secret of at least 32 bytes")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.MaxIdleConnsPerHost = 32
	return &HTTPAuthorizer{hook, secret, &http.Client{Timeout: 8 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (a *HTTPAuthorizer) post(ctx context.Context, address string, body any, out any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, address, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if a.hook != "" && a.secret != "" {
		req.Header.Set("Authorization", "Bearer "+a.secret)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return safeError("authorization_unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return safeError("authorization_denied")
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024+1))
	if err != nil || len(b) > 1024*1024 {
		return safeError("invalid_authorization_response")
	}
	if json.Unmarshal(b, out) != nil {
		return safeError("invalid_authorization_response")
	}
	return nil
}
func (a *HTTPAuthorizer) Authorize(ctx context.Context, token, name string, requested int) (Authorization, error) {
	var grant Authorization
	if !validToken(token) || !validName.MatchString(name) {
		return grant, safeError("invalid_identity")
	}
	if err := a.post(ctx, a.hook, map[string]any{"token": token, "tunnelName": name, "requestedPort": requested}, &grant); err != nil {
		return grant, err
	}
	if grant.UserID == "" || len(grant.UserID) > 256 || grant.TunnelID == "" || len(grant.TunnelID) > 256 || grant.Port < 1024 || grant.Port > 65535 || (requested != 0 && requested != grant.Port) {
		return grant, safeError("invalid_grant")
	}
	return grant, nil
}
