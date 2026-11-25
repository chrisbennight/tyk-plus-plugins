package driftreview

import (
	"bytes"
	"regexp"
	"slices"
	"strings"

	"github.com/go-json-experiment/json/jsontext"
)

// Flag is an advisory note about a definition or instructions under
// review. Flags point a reviewer at text worth a closer look; they never
// approve or reject anything, and text without flags can still be harmful.
type Flag struct {
	Name, Detail string
}

// longText is the length past which text is flagged as very long; long
// descriptions leave room to hide instructions.
const longText = 2000

// maxChecked is the largest text checked for flags other than its length;
// checking much larger text would cost time and memory out of proportion.
const maxChecked = 1 << 20

var (
	instructionLike = regexp.MustCompile(`(?i)\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|earlier|other)\b[^.\n]{0,20}\b(instructions?|rules?|prompts?)\b` +
		`|\b(system|developer) prompt\b|\byou (must|should) (always|never|first)\b|\bdo not (tell|mention|reveal|inform)\b` +
		`|\bbefore (using|calling) (this|any|other)\b|</?(important|system|instructions?)>`)
	reference = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>]+|(~|\$HOME)/[\w./-]+|/(etc|root|home|var)/[\w./-]+|\.(ssh|aws|env|netrc)\b`)
)

// Flags returns the advisory flags of a tool definition or of instructions:
// instruction-like phrases, invisible or look-alike characters, references
// to other tools, files or web addresses, and very long text. Every string in
// a definition is checked, including member names. tools names the proxy's
// other tools, whose mention is a reference.
func Flags(content jsontext.Value, text string, tools []string) []Flag {
	if len(content)+len(text) > maxChecked {
		return []Flag{{"long", "is too large to check for other flags; review it with cedar-policy drift show"}}
	}
	strs := []string{text}
	if len(content) > 0 {
		strs = stringsOf(content)
	}
	all := strings.Join(strs, "\n")
	var flags []Flag
	if m := instructionLike.FindString(all); m != "" {
		flags = append(flags, Flag{"instructions", "contains instruction-like text: “" + VisibleLine(m) + "”"})
	}
	invisible, lookAlike := 0, 0
	for _, s := range strs {
		_, i, l := Visible(s)
		invisible, lookAlike = invisible+i, lookAlike+l
	}
	if invisible > 0 || lookAlike > 0 {
		flags = append(flags, Flag{"hidden", "contains invisible or look-alike characters"})
	}
	if m := reference.FindString(all); m != "" {
		flags = append(flags, Flag{"reference", "refers to a file or web address: " + VisibleLine(m)})
	}
	lower := strings.ToLower(all)
	for _, tool := range tools {
		// The plain substring test is cheap, so the pattern is built only
		// for tools the text may mention.
		if len(tool) > 2 && strings.Contains(lower, strings.ToLower(tool)) && regexp.MustCompile(`\b`+regexp.QuoteMeta(strings.ToLower(tool))+`\b`).MatchString(lower) {
			flags = append(flags, Flag{"reference", "mentions another tool: " + ShownName(tool)})
			break
		}
	}
	if len(all) > longText {
		flags = append(flags, Flag{"long", "is very long"})
	}
	return flags
}

// stringsOf returns every string in a JSON value, member names included.
func stringsOf(value jsontext.Value) []string {
	var strs []string
	dec := jsontext.NewDecoder(bytes.NewReader(value))
	for {
		token, err := dec.ReadToken()
		if err != nil {
			return strs
		}
		if token.Kind() == '"' {
			strs = append(strs, token.String())
		}
	}
}

// OtherTools returns a proxy's tools other than one, for Flags.
func OtherTools(tools []string, tool string) []string {
	return slices.DeleteFunc(slices.Clone(tools), func(t string) bool { return t == tool })
}
