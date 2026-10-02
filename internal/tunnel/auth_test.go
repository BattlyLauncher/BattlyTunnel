package tunnel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPrivateHook(t *testing.T) {
	port := 30001
	denied := false
	redirect := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("s", 32) {
			t.Error("missing operator authentication")
		}
		var body struct {
			Token         string
			TunnelName    string
			RequestedPort int
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Token != "test-token" || body.TunnelName != "qa" {
			t.Error("invalid request")
		}
		if redirect {
			http.Redirect(w, r, "http://127.0.0.1:1", 302)
			return
		}
		if denied {
			w.WriteHeader(403)
			return
		}
		_ = json.NewEncoder(w).Encode(Authorization{"user-id", "tunnel-id", port})
	}))
	defer ts.Close()
	a, e := NewHTTPAuthorizer(ts.URL, strings.Repeat("s", 32))
	if e != nil {
		t.Fatal(e)
	}
	defer a.client.CloseIdleConnections()
	if _, e = a.Authorize(context.Background(), "test-token", "qa", 30001); e != nil {
		t.Fatal(e)
	}
	port++
	if _, e = a.Authorize(context.Background(), "test-token", "qa", 30001); e == nil {
		t.Fatal("wrong port accepted")
	}
	denied = true
	if _, e = a.Authorize(context.Background(), "test-token", "qa", 0); e == nil {
		t.Fatal("denied identity accepted")
	}
	denied = false
	redirect = true
	if _, e = a.Authorize(context.Background(), "test-token", "qa", 0); e == nil {
		t.Fatal("redirect accepted")
	}
	for _, u := range []string{"http://example.com/auth", "https://user:pass@example.com/auth", "https://example.com/auth?token=x", ""} {
		if _, e = NewHTTPAuthorizer(u, strings.Repeat("s", 32)); e == nil {
			t.Fatal("unsafe endpoint accepted")
		}
	}
	if _, e = NewHTTPAuthorizer(ts.URL, "short"); e == nil {
		t.Fatal("short operator secret accepted")
	}
}
