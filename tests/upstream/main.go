package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type arguments struct {
	Count *int `json:"count,omitempty"`
}

func main() {
	// The server declares instructions, so the gateway's check of them can be
	// tested against approved text that differs.
	server := mcp.NewServer(&mcp.Implementation{Name: "test-upstream", Version: "1"},
		&mcp.ServerOptions{Instructions: "Use lookup for records."})
	var lastArgs atomic.Pointer[arguments]
	// codemode.spoof uses the prefix the gateway reserves for Code Mode, so the
	// gateway must hide it and refuse calls to it.
	for name, reply := range map[string]string{"lookup": "found", "change": "updated", "codemode.spoof": "spoofed"} {
		tool := &mcp.Tool{Name: name, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}
		mcp.AddTool(server, tool, func(_ context.Context, _ *mcp.CallToolRequest, args arguments) (*mcp.CallToolResult, any, error) {
			lastArgs.Store(&args)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: reply}}}, nil, nil
		})
	}

	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server },
		// UPSTREAM_STREAM selects streamed replies and UPSTREAM_SESSIONS the
		// older protocol's sessions, so the gateway is tested against each kind
		// of upstream. A server that keeps sessions accepts only the older protocol.
		&mcp.StreamableHTTPOptions{Stateless: os.Getenv("UPSTREAM_SESSIONS") == "", JSONResponse: os.Getenv("UPSTREAM_STREAM") == ""})
	var requests atomic.Uint64
	// lastVersion records the protocol version the gateway used on the last
	// request, so tests can confirm it matches what the client negotiated.
	var lastVersion atomic.Value
	lastVersion.Store("")
	// The gateway's token exchange: this server also acts as the identity
	// provider's token endpoint, and accepts only tokens it issued itself, so
	// a caller's own credential is never accepted.
	var exchanges, withIssuedToken atomic.Uint64
	var issued sync.Map
	http.HandleFunc("/exchange", func(w http.ResponseWriter, r *http.Request) {
		exchanges.Add(1)
		refuse := func(code string) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": code})
		}
		client, secret, ok := r.BasicAuth()
		if r.Method != http.MethodPost || r.ParseForm() != nil || !ok || client != "gateway" || secret != "test-only-secret" ||
			r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" ||
			r.PostForm.Get("subject_token_type") != "urn:ietf:params:oauth:token-type:access_token" ||
			r.PostForm.Get("resource") != "http://upstream:8000/mcp" || r.PostForm.Has("audience") || r.PostForm.Get("subject_token") == "" {
			refuse("invalid_request")
			return
		}
		// A caller whose subject is "refused" is refused, so the gateway's
		// handling of a failed exchange can be tested.
		if subjectOf(r.PostForm.Get("subject_token")) == "refused" {
			refuse("invalid_grant")
			return
		}
		random := make([]byte, 16)
		rand.Read(random)
		token := "issued-" + hex.EncodeToString(random)
		// A caller whose subject is "echo" gets its own token back, as a
		// faulty provider or adapter might send it.
		if subjectOf(r.PostForm.Get("subject_token")) == "echo" {
			token = r.PostForm.Get("subject_token")
		}
		issued.Store(token, true)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": token, "token_type": "Bearer",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token", "expires_in": 300})
	})
	http.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		lastVersion.Store(r.Header.Get("MCP-Protocol-Version"))
		if authorization := r.Header.Get("Authorization"); authorization != "" {
			token, ok := strings.CutPrefix(authorization, "Bearer ")
			if _, known := issued.Load(token); !ok || !known {
				http.Error(w, "unexpected caller credential", http.StatusBadRequest)
				return
			}
			withIssuedToken.Add(1)
		}
		if r.Header.Get("X-API-Key") != "" {
			http.Error(w, "unexpected caller credential", http.StatusBadRequest)
			return
		}
		// The gateway removes the header that marks Code Mode's nested calls.
		if r.Header.Get("X-Code-Mode-Call") != "" {
			http.Error(w, "unexpected Code Mode header", http.StatusBadRequest)
			return
		}
		handler.ServeHTTP(w, r)
	})
	http.HandleFunc("/requests", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"requests": requests.Load(), "arguments": lastArgs.Load(), "protocolVersion": lastVersion.Load(),
			"exchanges": exchanges.Load(), "withIssuedToken": withIssuedToken.Load()})
	})
	log.Fatal(http.ListenAndServe(":8000", nil))
}

// subjectOf reads a JWT's sub claim without verifying it; the gateway has
// already verified the token.
func subjectOf(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	var claims struct {
		Sub string `json:"sub"`
	}
	if err != nil || json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	return claims.Sub
}
