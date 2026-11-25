package policy

import (
	"encoding/json"

	"github.com/cedar-policy/cedar-go"
)

// DecideBuiltIn decides a call to a tool the plug-in answers itself, such as
// codemode.execute. Such a tool ships with the plug-in rather than an
// upstream, so it has no reviewed facts, tags or upstream annotations, and its
// arguments are never facts. Rules grant it as they grant any tool: by its
// name, its proxy or the caller.
func (s *Snapshot) DecideBuiltIn(who Caller, proxy, upstream, name string) (string, []string) {
	builtIn := &tool{}
	if err := builtIn.prepare(name); err != nil {
		return "invalid_call", nil
	}
	principal, entities := callerEntity(who)
	toolID, _ := json.Marshal([2]string{proxy, name})
	resource := cedar.NewEntityUID("Tool", cedar.String(toolID))
	entities[resource] = toolEntity(resource, proxy, upstream, name, builtIn, false)
	return s.evaluate(entities, cedar.Request{
		Principal: principal, Action: cedar.NewEntityUID("Action", "tools/call"), Resource: resource, Context: noArguments(),
	})
}
