package codemode

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// The tools the plug-in answers on a Code Mode proxy, in the order they are
// listed.
const (
	SearchTool   = "codemode.search"
	DescribeTool = "codemode.describe"
	LimitsTool   = "codemode.limits"
)

// Tools lists the Code Mode tools in the order they are listed.
var Tools = []string{SearchTool, DescribeTool, LimitsTool, ExecuteTool}

// IsTool reports whether a name is one of the tools the plug-in answers.
func IsTool(name string) bool {
	for _, t := range Tools {
		if t == name {
			return true
		}
	}
	return false
}

// definitions are the Code Mode tools as clients see them. They ship with the
// plug-in, so they are not drift reviewed.
var definitions = map[string]any{
	SearchTool: map[string]any{
		"name": SearchTool,
		"description": "Find tools you can call from a Code Mode program, on this proxy and the other proxies where Code Mode is on. " +
			"Every word of the query must appear in a tool's name or description; leave it out to list every tool you can use. " +
			"detail \"summary\" returns names and the first line of each description; \"full\" adds each input schema.",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{
			"query":  map[string]any{"type": "string"},
			"detail": map[string]any{"type": "string", "enum": []string{"summary", "full"}},
			"limit":  map[string]any{"type": "integer", "minimum": 1, "maximum": maxSearchLimit},
			"cursor": map[string]any{"type": "string", "description": "The nextCursor of an earlier search with the same query."},
		}},
		"annotations": map[string]any{"readOnlyHint": true},
	},
	DescribeTool: map[string]any{
		"name":        DescribeTool,
		"description": "Describe one tool you can call from a Code Mode program: its approved input schema and the exact form to call it with.",
		"inputSchema": map[string]any{"type": "object", "required": []string{"proxy", "name"}, "properties": map[string]any{
			"proxy": map[string]any{"type": "string"},
			"name":  map[string]any{"type": "string"},
		}},
		"annotations": map[string]any{"readOnlyHint": true},
	},
	LimitsTool: map[string]any{
		"name":        LimitsTool,
		"description": "Report the limits on Code Mode runs on this gateway. A run may lower any of them with codemode.execute's limits or timeout_seconds, but not raise them.",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		"annotations": map[string]any{"readOnlyHint": true},
	},
	ExecuteTool: map[string]any{
		"name": ExecuteTool,
		"description": "Run a JavaScript program that calls tools and returns one result, so intermediate results stay out of your context. " +
			"source is the body of an async function; input is available as `input`. " +
			"Call a tool with `await connectors[\"proxy\"][\"tool\"](arguments)`, using the call form codemode.describe gives; " +
			"it resolves to the tool's result, or rejects with an error carrying the code and message a direct call would get. " +
			"Calls may run in parallel with Promise.all. console.log output is returned with the result. " +
			"Every call is authorized as if you made it directly. See codemode.limits for the limits on a run.",
		"inputSchema": map[string]any{"type": "object", "required": []string{"source"}, "properties": map[string]any{
			"source":          map[string]any{"type": "string"},
			"input":           map[string]any{},
			"timeout_seconds": map[string]any{"type": "number", "exclusiveMinimum": 0},
			"limits": map[string]any{"type": "object", "properties": map[string]any{
				"run_ms": map[string]any{"type": "integer"}, "call_ms": map[string]any{"type": "integer"},
				"memory_bytes": map[string]any{"type": "integer"}, "calls": map[string]any{"type": "integer"},
				"calls_at_once": map[string]any{"type": "integer"}, "program_bytes": map[string]any{"type": "integer"},
				"console_bytes": map[string]any{"type": "integer"}, "value_bytes": map[string]any{"type": "integer"},
			}},
		}},
	},
}

// Definition returns a Code Mode tool's definition as clients see it.
func Definition(name string) json.RawMessage {
	data, _ := json.Marshal(definitions[name])
	return data
}

// Entry is one tool a caller can call from a program.
type Entry struct {
	Proxy, Name string
	// Definition is the approved upstream definition, or nil when the tool
	// was approved without one.
	Definition json.RawMessage
}

// CallForm is the expression a program uses to call a tool.
func CallForm(proxy, name string) string {
	p, _ := json.Marshal(proxy)
	n, _ := json.Marshal(name)
	return fmt.Sprintf("connectors[%s][%s]", p, n)
}

type approved struct {
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

func (e Entry) approved() approved {
	var a approved
	_ = json.Unmarshal(e.Definition, &a)
	return a
}

// Describe returns what codemode.describe reports for a tool.
func Describe(e Entry) map[string]any {
	a := e.approved()
	out := map[string]any{"proxy": e.Proxy, "name": e.Name, "call": CallForm(e.Proxy, e.Name), "description": a.Description}
	if len(a.InputSchema) > 0 {
		out["inputSchema"] = a.InputSchema
	} else {
		out["note"] = "No input schema was approved for this tool."
	}
	return out
}

// Search limits.
const (
	defaultSearchLimit = 20
	maxSearchLimit     = 100
)

// ErrCursor reports a cursor from another query or policy set.
var ErrCursor = errors.New("the cursor is not from this search; search again without it")

// cursor records the last tool a page returned, so the next page resumes
// after it in proxy and name order even if tools became callable or stopped
// being callable in between.
type cursor struct {
	Version string `json:"v"`
	Query   string `json:"q"`
	Proxy   string `json:"p"`
	Name    string `json:"n"`
}

// after reports whether e comes after the tool a cursor names.
func (c cursor) after(e Entry) bool {
	return e.Proxy > c.Proxy || e.Proxy == c.Proxy && e.Name > c.Name
}

// Search returns what codemode.search reports: the entries matching query,
// one page at a time. Entries must be in proxy and name order. version
// identifies the policy set, so a cursor from another set is refused.
func Search(entries []Entry, query, detail string, limit int, after, version string) (map[string]any, error) {
	if limit <= 0 {
		limit = defaultSearchLimit
	}
	limit = min(limit, maxSearchLimit)
	full := detail == "full"
	if detail != "" && detail != "summary" && !full {
		return nil, errors.New(`detail must be "summary" or "full"`)
	}
	var resume *cursor
	if after != "" {
		data, err := base64.RawURLEncoding.DecodeString(after)
		var c cursor
		if err != nil || json.Unmarshal(data, &c) != nil || c.Version != version || c.Query != query {
			return nil, ErrCursor
		}
		resume = &c
	}
	terms := strings.Fields(strings.ToLower(query))
	var matched []Entry
	for _, e := range entries {
		text := strings.ToLower(e.Name + "\n" + e.approved().Description)
		all := true
		for _, term := range terms {
			if !strings.Contains(text, term) {
				all = false
				break
			}
		}
		if all && (resume == nil || resume.after(e)) {
			matched = append(matched, e)
		}
	}
	tools := []map[string]any{}
	for i := 0; i < len(matched) && len(tools) < limit; i++ {
		e := matched[i]
		a := e.approved()
		item := map[string]any{"proxy": e.Proxy, "name": e.Name, "call": CallForm(e.Proxy, e.Name)}
		if full {
			item["description"] = a.Description
			if len(a.InputSchema) > 0 {
				item["inputSchema"] = a.InputSchema
			}
		} else {
			item["description"], _, _ = strings.Cut(a.Description, "\n")
		}
		tools = append(tools, item)
	}
	out := map[string]any{"tools": tools}
	if len(tools) < len(matched) {
		last := matched[len(tools)-1]
		data, _ := json.Marshal(cursor{Version: version, Query: query, Proxy: last.Proxy, Name: last.Name})
		out["nextCursor"] = base64.RawURLEncoding.EncodeToString(data)
	}
	return out, nil
}

// LimitsReport returns what codemode.limits reports.
func LimitsReport(s *Settings) map[string]any {
	return map[string]any{
		"run_ms": s.Max.RunMillis, "call_ms": s.Max.CallMillis, "memory_bytes": s.Max.MemoryBytes,
		"calls": s.Max.Calls, "calls_at_once": s.Max.CallsAtOnce, "program_bytes": s.Max.ProgramBytes,
		"console_bytes": s.Max.ConsoleBytes, "value_bytes": s.Max.ValueBytes, "runs_at_once": s.Runs,
		"note": "Every limit except runs_at_once is a maximum for one run, which a run may lower with codemode.execute's limits or timeout_seconds but not raise. runs_at_once is this gateway's limit on runs at the same time.",
	}
}

// EditList edits one tools/list result: it removes upstream tools whose names
// start with the reserved prefix, reporting each, and appends add. A message
// that is not a tools/list result is returned unchanged.
func EditList(message []byte, add []json.RawMessage, report func(name string)) []byte {
	var envelope map[string]json.RawMessage
	if json.Unmarshal(message, &envelope) != nil || envelope["result"] == nil {
		return message
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(envelope["result"], &result) != nil || result == nil {
		return message
	}
	var tools []json.RawMessage
	if json.Unmarshal(result["tools"], &tools) != nil {
		return message
	}
	kept := make([]json.RawMessage, 0, len(tools)+len(add))
	changed := len(add) > 0
	for _, tool := range tools {
		var named struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(tool, &named) == nil && strings.HasPrefix(named.Name, ToolPrefix) {
			report(named.Name)
			changed = true
			continue
		}
		kept = append(kept, tool)
	}
	if !changed {
		return message
	}
	result["tools"], _ = json.Marshal(append(kept, add...))
	envelope["result"], _ = json.Marshal(result)
	out, err := json.Marshal(envelope)
	if err != nil {
		return message
	}
	return out
}
