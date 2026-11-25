package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/codemode"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/identity"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/policy"
	"github.com/chrisbennight/tyk-plus-plugins/sandbox/protocol"
)

// Code Mode state, set once when the plug-in loads.
var (
	// codeMode holds the settings, or nil when Code Mode is not configured.
	codeMode *codemode.Settings
	// codeModeProblem explains why configured Code Mode cannot run.
	codeModeProblem string
	runner          *codemode.Runner
	nestedCalls     = &codemode.Registry{}
	gatewayCalls    *codemode.Gateway
)

func init() {
	tyk := codemode.Tyk{ListenPort: 8080, WriteTimeout: 120 * time.Second}
	if config.Global != nil {
		conf := config.Global()
		if conf.ListenPort != 0 {
			tyk.ListenPort = conf.ListenPort
		}
		tyk.ListenAddress = conf.ListenAddress
		tyk.UseTLS = conf.HttpServerOptions.UseSSL
		if conf.HttpServerOptions.WriteTimeout > 0 {
			tyk.WriteTimeout = time.Duration(conf.HttpServerOptions.WriteTimeout) * time.Second
		}
	}
	settings, err := codemode.Load(os.Getenv, tyk)
	if settings == nil {
		return
	}
	codeMode = settings
	if err != nil {
		codeModeProblem = err.Error()
		slog.Error("Code Mode is unavailable", "reason", codeModeProblem)
		return
	}
	runner = codemode.NewRunner(settings)
	gatewayCalls = &codemode.Gateway{Base: settings.Gateway, Paths: settings.Proxies, Client: codemode.NewClient(), Registry: nestedCalls}
	slog.Info("Code Mode is on", "proxies", len(settings.Proxies), "sandbox", settings.Address)
}

// bearerKey keys the caller's bearer credential in the request context.
type bearerKey struct{}

// Capture is a Tyk hook that runs right after authentication. Tyk removes
// credential headers before the authorization hook runs, so this keeps a
// token caller's bearer credential in the request's own context, where a
// Code Mode run can present it again on nested calls. It is never logged.
func Capture(_ http.ResponseWriter, r *http.Request) {
	if codeMode == nil {
		return
	}
	if bearer := r.Header.Get("Authorization"); bearer != "" {
		*r = *r.WithContext(context.WithValue(r.Context(), bearerKey{}, bearer))
	}
}

// takeNested removes the nested-call header from a request and returns the
// nested call it identifies. A header the plug-in did not send identifies
// nothing.
func takeNested(r *http.Request) (codemode.Nested, bool) {
	values := r.Header.Values(codemode.CallHeader)
	r.Header.Del(codemode.CallHeader)
	if len(values) != 1 {
		return codemode.Nested{}, false
	}
	return nestedCalls.Lookup(values[0])
}

// codeModeOn reports whether Code Mode answers its tools on a proxy.
func codeModeOn(proxy string) bool {
	if codeMode == nil {
		return false
	}
	_, on := codeMode.Proxies[proxy]
	return on
}

// executeArguments are the arguments of codemode.execute.
type executeArguments struct {
	Source         string          `json:"source"`
	Input          json.RawMessage `json:"input"`
	TimeoutSeconds float64         `json:"timeout_seconds"`
	Limits         codemode.Limits `json:"limits"`
}

// execute runs a program for a caller the gateway permitted to call
// codemode.execute, and writes the tool result.
func execute(w http.ResponseWriter, r *http.Request, id json.RawMessage, params json.RawMessage, who policy.Caller, method identity.Method, proxy string) {
	if codeModeProblem != "" {
		writeToolError(w, id, "unavailable", "Code Mode is unavailable on this gateway", nil)
		return
	}
	var call struct {
		Arguments executeArguments `json:"arguments"`
		Meta      json.RawMessage  `json:"_meta"`
	}
	if err := json.Unmarshal(params, &call); err != nil || call.Arguments.Source == "" {
		writeToolError(w, id, "invalid", "codemode.execute needs a source string, and optional input, timeout_seconds and limits", nil)
		return
	}
	args := call.Arguments
	requested := args.Limits
	if args.TimeoutSeconds > 0 {
		// A positive timeout is at least a millisecond; zero would mean
		// the maximum.
		requested.RunMillis = int64(math.Ceil(args.TimeoutSeconds * 1000))
	}
	limits := requested.Within(codeMode.Max)
	if string(args.Input) == "null" {
		args.Input = nil
	}

	origin := codemode.Origin{Proxy: proxy, Version: r.Header.Get("MCP-Protocol-Version"), Session: r.Header.Get("Mcp-Session-Id"),
		Meta: call.Meta, NamedHeaders: r.Header.Get("Mcp-Method") != "", Credential: http.Header{}}
	// Only the credential that identified the caller is presented again.
	if method == identity.Token {
		if bearer, _ := r.Context().Value(bearerKey{}).(string); bearer != "" {
			origin.Credential.Set("Authorization", bearer)
		}
	} else if key := ctx.GetAuthToken(r); key != "" {
		origin.Credential.Set(keyHeader(r), key)
	}

	run := codemode.NewRunID()
	sum := sha256.Sum256([]byte(args.Source))
	session := gatewayCalls.Session(origin, run, limits.ValueBytes)
	// The sessions the run opened are closed after its result is written,
	// so closing them never delays the reply.
	defer func() { go session.Close() }()
	started := time.Now()
	out := runner.Run(r.Context(), codemode.Request{
		Source: args.Source, Input: args.Input, Limits: limits, Call: session.Call,
		OnCall: func(c codemode.CallRecord) {
			// A call to a proxy without Code Mode never reaches the gateway,
			// so its names are only program data and are not logged.
			if _, known := codeMode.Proxies[c.Proxy]; !known {
				c.Proxy, c.Tool = "", ""
			}
			slog.Info("Code Mode call", "run", run, "call", c.ID, "proxy", c.Proxy, "tool", c.Tool, "outcome", c.Outcome)
		},
	})
	outcome, kind := "result", ""
	if out.Failure != nil {
		outcome, kind = "failed", out.Failure.Kind
	}
	slog.Info("Code Mode run", "run", run, "identity", method, "issuer", who.Issuer, "subject", who.Subject, "proxy", proxy,
		"program_sha256", hex.EncodeToString(sum[:]), "backend", out.Backend, "started", started.UTC().Format(time.RFC3339Nano),
		"duration_ms", time.Since(started).Milliseconds(), "calls", out.Calls, "refused", out.Refused, "failed", out.Failed,
		"unknown", out.Unknown, "outcome", outcome, "failure_kind", kind)
	if out.Failure != nil {
		writeToolError(w, id, out.Failure.Kind, failureText(out.Failure), out.Console)
		return
	}
	result := map[string]any{"result": out.Result, "console": nonNil(out.Console)}
	text, _ := json.Marshal(result)
	writeResult(w, id, map[string]any{"content": []map[string]any{{"type": "text", "text": string(text)}}, "structuredContent": result})
}

// keyHeader is the header the proxy reads keys from: the name of its
// header API key security scheme.
func keyHeader(r *http.Request) string {
	if oas := ctx.GetOASDefinition(r); oas != nil && oas.Components != nil {
		for _, scheme := range oas.Components.SecuritySchemes {
			if scheme != nil && scheme.Value != nil && scheme.Value.Type == "apiKey" && scheme.Value.In == "header" && scheme.Value.Name != "" {
				return scheme.Value.Name
			}
		}
	}
	return "Authorization"
}

func failureText(f *protocol.Failure) string {
	switch f.Kind {
	case protocol.KindBusy:
		return "Code Mode is busy; try again shortly. " + f.Message
	case protocol.KindLimit, protocol.KindException:
		return f.Message
	case codemode.KindCancelled:
		return f.Message
	}
	// Other failures are the gateway's or the sandbox host's own, and their
	// details stay in the gateway's log.
	slog.Warn("Code Mode run failed", "kind", f.Kind, "reason", f.Message)
	return "Code Mode could not complete the run"
}

func nonNil(lines []string) []string {
	if lines == nil {
		return []string{}
	}
	return lines
}

// writeToolError reports a run that did not produce a result as a tool error,
// so the model sees why.
func writeToolError(w http.ResponseWriter, id json.RawMessage, kind, message string, console []string) {
	structured := map[string]any{"error": map[string]any{"kind": kind, "message": message}, "console": nonNil(console)}
	writeResult(w, id, map[string]any{"isError": true, "content": []map[string]any{{"type": "text", "text": message}}, "structuredContent": structured})
}

func writeResult(w http.ResponseWriter, id json.RawMessage, result any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

// isCodeModeTool reports whether a tool name belongs to Code Mode.
func isCodeModeTool(name string) bool { return strings.HasPrefix(name, codemode.ToolPrefix) }
