package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
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
	for name, reply := range map[string]string{"lookup": "found", "change": "updated"} {
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
	http.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		lastVersion.Store(r.Header.Get("MCP-Protocol-Version"))
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-API-Key") != "" {
			http.Error(w, "unexpected caller credential", http.StatusBadRequest)
			return
		}
		handler.ServeHTTP(w, r)
	})
	http.HandleFunc("/requests", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"requests": requests.Load(), "arguments": lastArgs.Load(), "protocolVersion": lastVersion.Load()})
	})
	log.Fatal(http.ListenAndServe(":8000", nil))
}
