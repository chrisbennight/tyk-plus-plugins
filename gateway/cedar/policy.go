package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/cedar-policy/cedar-go/x/exp/schema/validate"
)

//go:embed schema.cedarschema
var inputSchema []byte

type tool struct {
	ReadOnly *bool  `json:"readOnly"`
	Risk     string `json:"risk"`
	Upstream struct {
		ReadOnlyHint *bool `json:"readOnlyHint"`
	} `json:"upstreamAnnotations"`
	Arguments map[string]string `json:"arguments"`
}

type snapshot struct {
	version  string
	policies *cedar.PolicySet
	tools    map[string]map[string]tool
}

func compile(rules, inventory []byte, version string) (*snapshot, error) {
	var schemaDoc schema.Schema
	if err := schemaDoc.UnmarshalCedar(inputSchema); err != nil {
		return nil, err
	}
	resolved, err := schemaDoc.Resolve()
	if err != nil {
		return nil, err
	}
	validator := validate.New(resolved)
	list, err := cedar.NewPolicyListFromBytes("rules.cedar", rules)
	if err != nil {
		return nil, err
	}
	s := &snapshot{version: version, policies: cedar.NewPolicySet()}
	for i, p := range list {
		id := cedar.PolicyID(p.Annotations()["id"])
		if id == "" {
			id = cedar.PolicyID(fmt.Sprintf("policy%d", i))
		}
		if err := validator.Policy(string(id), (*ast.Policy)(p.AST())); err != nil {
			return nil, err
		}
		if !s.policies.Add(id, p) {
			return nil, fmt.Errorf("duplicate policy ID %s", id)
		}
	}
	if err := json.Unmarshal(inventory, &s.tools); err != nil {
		return nil, err
	}
	for _, tools := range s.tools {
		for name, t := range tools {
			if name == "" || t.ReadOnly == nil {
				return nil, fmt.Errorf("tool %q needs a reviewed readOnly classification", name)
			}
			for _, kind := range t.Arguments {
				switch kind {
				case "string", "long", "boolean":
				default:
					return nil, fmt.Errorf("unsupported argument type %q", kind)
				}
			}
		}
	}
	return s, nil
}

var active struct {
	sync.Mutex
	version  string
	snapshot *snapshot
}

// Operators replace files by rename. Serialize reads and activation so an older
// observation cannot overwrite a newer snapshot after validation.
func current() *snapshot {
	active.Lock()
	defer active.Unlock()
	dir := "/opt/tyk-gateway/cedar"
	rules, e1 := os.ReadFile(filepath.Join(dir, "rules.cedar"))
	tools, e2 := os.ReadFile(filepath.Join(dir, "tools.json"))
	if e1 != nil || e2 != nil {
		return active.snapshot
	}
	version := fmt.Sprintf("%x.%x", sha256.Sum256(rules), sha256.Sum256(tools))
	if version != active.version {
		next, err := compile(rules, tools, version)
		if err == nil {
			active.snapshot = next
		} else {
			slog.Warn("Cedar configuration rejected", "candidate", version, "error", err.Error())
		}
		active.version = version
	}
	return active.snapshot
}
