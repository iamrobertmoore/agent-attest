package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func mk(hdr map[string]any) string {
	b, _ := json.Marshal(hdr)
	return base64.RawURLEncoding.EncodeToString(b) + ".e30.sig"
}

func TestLooksLikePKI(t *testing.T) {
	// An OIDC token: kid, no x5c. This is what you get if token_type is omitted, and
	// the whole point of the check is to catch it before the VM is torn down.
	if err := looksLikePKI(mk(map[string]any{"alg": "RS256", "kid": "abc"})); err == nil {
		t.Fatal("an OIDC token must be reported")
	} else if !strings.Contains(err.Error(), "OIDC") {
		t.Fatalf("unhelpful message: %v", err)
	}
	// Wrong chain depth.
	if err := looksLikePKI(mk(map[string]any{"alg": "RS256", "x5c": []string{"a", "b"}})); err == nil {
		t.Fatal("a 2-cert chain must be reported")
	}
	// Good.
	if err := looksLikePKI(mk(map[string]any{"alg": "RS256", "x5c": []string{"a", "b", "c"}})); err != nil {
		t.Fatalf("valid PKI header rejected: %v", err)
	}
	if err := looksLikePKI("not-a-jwt"); err == nil {
		t.Fatal("garbage must be reported")
	}
}
