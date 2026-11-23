package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync/atomic"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type arguments struct {
	Count *int `json:"count,omitempty"`
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "test-upstream", Version: "1"}, nil)
	var lastArgs atomic.Pointer[arguments]
	for name, reply := range map[string]string{"lookup": "found", "change": "updated"} {
		tool := &mcp.Tool{Name: name, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}
		mcp.AddTool(server, tool, func(_ context.Context, _ *mcp.CallToolRequest, args arguments) (*mcp.CallToolResult, any, error) {
			lastArgs.Store(&args)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: reply}}}, nil, nil
		})
	}

	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	var requests atomic.Uint64
	http.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "" {
			http.Error(w, "unexpected caller credential", http.StatusBadRequest)
			return
		}
		handler.ServeHTTP(w, r)
	})
	http.HandleFunc("/requests", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"requests": requests.Load(), "arguments": lastArgs.Load()})
	})
	log.Fatal(http.ListenAndServe(":8000", nil))
}
