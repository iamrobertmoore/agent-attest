// Command capture-token runs inside a Google Confidential Space VM, asks the launcher
// for a PKI attestation token, and gets it out of the enclave before the VM stops.
//
// WHY THIS EXISTS
// ---------------
// Our browser verifier implements the PKI path: tokens carrying an `x5c` chain that
// validates against Google's Confidential Space Root CA. The default token a workload
// receives is the OIDC variant, which has a `kid` and no `x5c` at all, so it cannot be
// verified this way. Asking for `token_type: "PKI"` is the whole difference.
//
// THE THING THAT WILL LOSE YOU A RUN
// ----------------------------------
// On a production Confidential Space image the VM stops the moment this program exits,
// and stdout goes nowhere unless the image carries
//
//	LABEL "tee.launch_policy.log_redirect"="always"
//
// because the launch policy defaults to `debugonly`. Without that label you get a VM
// that boots, runs, stops, and leaves you nothing. A VM cannot be re-run in place
// either; you have to delete and recreate it.
//
// So this writes the token twice, to stdout and to a GCS object, and sleeps afterwards.
// Belt and braces on purpose: a run costs a VM creation and several minutes, and losing
// one to a missing label is a bad trade against a few lines of redundancy.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	// The launcher listens on this Unix socket inside the VM.
	socketPath = "/run/container_launcher/teeserver.sock"
	// Host is ignored; the socket is the real address.
	tokenURL = "http://localhost/v1/token"
)

type tokenRequest struct {
	Audience  string   `json:"audience"`
	Nonces    []string `json:"nonces"`
	TokenType string   `json:"token_type"`
}

func main() {
	log.SetFlags(0)
	log.Println("agent-attest capture-token starting")

	audience := envOr("ATTEST_AUDIENCE", "agent-attest-demo")
	bucket := os.Getenv("ATTEST_BUCKET")

	// Google's two documentation pages disagree on the permitted nonce size: one says
	// 10 to 74 bytes, the other 8 to 88. We use the intersection. A 32-byte random
	// value base64-encodes to 44 characters, comfortably inside both.
	nonce := os.Getenv("ATTEST_NONCE")
	if nonce == "" {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			log.Fatalf("generating nonce: %v", err)
		}
		nonce = base64.RawURLEncoding.EncodeToString(raw)
	}
	if len(nonce) < 10 || len(nonce) > 74 {
		log.Fatalf("nonce is %d bytes; must be 10 to 74", len(nonce))
	}

	log.Printf("audience=%q nonce=%q", audience, nonce)

	token, err := fetchToken(audience, nonce)
	if err != nil {
		log.Fatalf("fetching token: %v", err)
	}
	log.Printf("got a token, %d bytes", len(token))

	// Sanity-check before we celebrate. A token with no x5c is the OIDC variant, which
	// means token_type did not take effect, and the whole run is useless. Better to say
	// so here than to find out in the browser tomorrow.
	if err := looksLikePKI(token); err != nil {
		log.Printf("WARNING: %v", err)
	} else {
		log.Printf("token has an x5c chain, this is a PKI token")
	}

	// Output 1: stdout. Needs the log_redirect label on the image, see the file comment.
	fmt.Println("---ATTEST-TOKEN-BEGIN---")
	fmt.Println(token)
	fmt.Println("---ATTEST-TOKEN-END---")

	// Output 2: GCS, which survives the VM stopping and needs no log plumbing.
	if bucket != "" {
		if err := writeToGCS(context.Background(), bucket, "token.jwt", token); err != nil {
			log.Printf("WARNING: could not write to gs://%s: %v", bucket, err)
		} else {
			log.Printf("wrote gs://%s/token.jwt", bucket)
		}
		nonceNote := fmt.Sprintf("audience=%s\nnonce=%s\ncaptured=%s\n",
			audience, nonce, time.Now().UTC().Format(time.RFC3339))
		if err := writeToGCS(context.Background(), bucket, "token.meta.txt", nonceNote); err != nil {
			log.Printf("WARNING: could not write metadata: %v", err)
		}
	} else {
		log.Printf("ATTEST_BUCKET not set, so stdout is the only copy")
	}

	// Hold the VM open briefly. On a production image, exiting stops the instance, and
	// Cloud Logging can lag by a few seconds. Nothing here is secret and the workload
	// is finished; the wait only buys time for the logs to flush.
	log.Println("done, idling 120s so logs can flush")
	time.Sleep(120 * time.Second)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// fetchToken asks the launcher for a PKI attestation token.
func fetchToken(audience, nonce string) (string, error) {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
		Timeout: 30 * time.Second,
	}

	body, err := json.Marshal(tokenRequest{
		Audience: audience,
		Nonces:   []string{nonce},
		// The single most important field in this file. Without it you get an OIDC
		// token with a `kid` and no certificate chain, which the PKI verifier cannot
		// check at all.
		TokenType: "PKI",
	})
	if err != nil {
		return "", err
	}

	// The launcher rate-limits attestation requests to 5 per second per project per
	// region. One retry loop is enough to ride over a transient failure without
	// tripping that.
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
		res, err := client.Post(tokenURL, "application/json", bytes.NewReader(body))
		if err != nil {
			lastErr = fmt.Errorf("posting to launcher socket: %w", err)
			continue
		}
		payload, readErr := io.ReadAll(res.Body)
		res.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if res.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("launcher returned HTTP %d: %s",
				res.StatusCode, strings.TrimSpace(string(payload)))
			continue
		}
		return strings.TrimSpace(string(payload)), nil
	}
	return "", lastErr
}

// looksLikePKI checks the header for an x5c chain of the expected depth.
func looksLikePKI(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("token is not a three-part JWS")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("could not decode the protected header: %w", err)
	}
	var hdr struct {
		Alg string   `json:"alg"`
		X5c []string `json:"x5c"`
		Kid string   `json:"kid"`
	}
	if err := json.Unmarshal(raw, &hdr); err != nil {
		return fmt.Errorf("could not parse the protected header: %w", err)
	}
	if len(hdr.X5c) == 0 {
		return fmt.Errorf(
			"this is an OIDC token, not a PKI one (alg=%s kid=%s, no x5c). "+
				"token_type did not take effect", hdr.Alg, hdr.Kid)
	}
	if len(hdr.X5c) != 3 {
		return fmt.Errorf("x5c has %d certificates, expected 3", len(hdr.X5c))
	}
	if hdr.Alg != "RS256" {
		return fmt.Errorf("alg is %s, expected RS256", hdr.Alg)
	}
	return nil
}

// writeToGCS uploads using the VM service account's own credentials, via the metadata
// server. Done with plain HTTP rather than the cloud storage SDK so the container stays
// tiny and has no module dependencies at all.
func writeToGCS(ctx context.Context, bucket, object, content string) error {
	tok, err := metadataToken(ctx)
	if err != nil {
		return fmt.Errorf("getting a service account token: %w", err)
	}

	url := fmt.Sprintf(
		"https://storage.googleapis.com/upload/storage/v1/b/%s/o?uploadType=media&name=%s",
		bucket, object)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(content))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "text/plain")

	res, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		return fmt.Errorf("storage returned HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

func metadataToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("metadata server returned no access token")
	}
	return out.AccessToken, nil
}
