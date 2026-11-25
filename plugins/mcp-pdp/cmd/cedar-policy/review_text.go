package main

import (
	"bytes"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/policy"
	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
)

// visible returns text with every character a reviewer could miss written
// out by code point: invisible characters replace themselves, and
// look-alike characters keep their glyph followed by their code point. It
// also counts both, so a summary can say what was found. Line breaks are
// kept so text stays readable; visibleLine writes them out too.
//
// A look-alike is a non-ASCII letter, digit or mark in a word whose letters
// come from more than one script, as in a name spelled with one Cyrillic
// letter. Words written in a single script, such as café or привет, are
// left alone.
func visible(text string) (out string, invisible, lookAlike int) {
	return written(text, true)
}

// visibleLine is visible for text shown on one line, such as a name.
func visibleLine(text string) string {
	out, _, _ := written(text, false)
	return out
}

func written(text string, keepLines bool) (out string, invisible, lookAlike int) {
	var b strings.Builder
	for _, word := range splitWords(text) {
		mixed := mixesScripts(word)
		for _, r := range word {
			switch {
			case r == ' ' || (r == '\n' && keepLines):
				b.WriteRune(r)
			case isInvisible(r):
				invisible++
				fmt.Fprintf(&b, "⟨U+%04X⟩", r)
			case r == '⟨' || r == '⟩':
				// The markers themselves are written out, so text cannot
				// imitate a marker.
				lookAlike++
				fmt.Fprintf(&b, "⟨U+%04X⟩", r)
			case r > unicode.MaxASCII && mixed && (unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r)):
				lookAlike++
				fmt.Fprintf(&b, "%c⟨U+%04X⟩", r, r)
			default:
				b.WriteRune(r)
			}
		}
	}
	return b.String(), invisible, lookAlike
}

// mixesScripts reports whether a word's letters come from more than one
// script. Characters shared by scripts, such as digits and combining marks,
// belong to none.
func mixesScripts(word string) bool {
	first := ""
	for _, r := range word {
		if !unicode.IsLetter(r) {
			continue
		}
		script := scriptOf(r)
		switch {
		case script == "":
		case first == "":
			first = script
		case script != first:
			return true
		}
	}
	return false
}

func scriptOf(r rune) string {
	if r <= unicode.MaxASCII {
		return "Latin"
	}
	for name, table := range unicode.Scripts {
		if name != "Common" && name != "Inherited" && unicode.Is(table, r) {
			return name
		}
	}
	return ""
}

// isInvisible reports whether a character draws nothing a reviewer would
// see, or changes how nearby text is drawn: controls, format characters such
// as zero-width spaces and direction overrides, spaces other than the ASCII
// space, variation selectors, blank fillers, and unassigned code points.
func isInvisible(r rune) bool {
	switch {
	case r == utf8.RuneError,
		unicode.In(r, unicode.Cc, unicode.Cf, unicode.Co, unicode.Cs, unicode.Zl, unicode.Zp, unicode.Zs, unicode.Variation_Selector),
		r == 0x115F, r == 0x1160, r == 0x2800, r == 0x3164, r == 0xFFA0:
		return true
	}
	return !unicode.IsGraphic(r)
}

// splitWords splits text into runs of letters, digits and marks, and single
// other characters, keeping every character.
func splitWords(text string) []string {
	var words []string
	start := 0
	inWord := false
	for i, r := range text {
		wordRune := unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r)
		if i > start && (!wordRune || !inWord) {
			words = append(words, text[start:i])
			start = i
		}
		inWord = wordRune
	}
	if start < len(text) {
		words = append(words, text[start:])
	}
	return words
}

func hasASCIILetter(word string) bool {
	return strings.IndexFunc(word, func(r rune) bool { return r <= unicode.MaxASCII && unicode.IsLetter(r) }) >= 0
}

// maxDiffLines bounds the lines a text diff compares; longer texts are shown
// whole instead.
const maxDiffLines = 2000

// lineDiff writes a line diff of two texts, made visible: unchanged lines
// with two spaces, removed lines with "- " and added lines with "+ ".
func lineDiff(b *strings.Builder, before, after string) {
	old, new := strings.Split(before, "\n"), strings.Split(after, "\n")
	if len(old) > maxDiffLines || len(new) > maxDiffLines {
		writeLines(b, "- ", old)
		writeLines(b, "+ ", new)
		return
	}
	// common[i][j] is the length of the longest common subsequence of
	// old[i:] and new[j:].
	common := make([][]int, len(old)+1)
	for i := range common {
		common[i] = make([]int, len(new)+1)
	}
	for i := len(old) - 1; i >= 0; i-- {
		for j := len(new) - 1; j >= 0; j-- {
			if old[i] == new[j] {
				common[i][j] = common[i+1][j+1] + 1
			} else {
				common[i][j] = max(common[i+1][j], common[i][j+1])
			}
		}
	}
	i, j := 0, 0
	for i < len(old) || j < len(new) {
		switch {
		case i < len(old) && j < len(new) && old[i] == new[j]:
			writeLines(b, "  ", old[i:i+1])
			i, j = i+1, j+1
		case i < len(old) && (j == len(new) || common[i+1][j] >= common[i][j+1]):
			writeLines(b, "- ", old[i:i+1])
			i++
		default:
			writeLines(b, "+ ", new[j:j+1])
			j++
		}
	}
}

func writeLines(b *strings.Builder, prefix string, lines []string) {
	for _, line := range lines {
		shown, _, _ := visible(line)
		b.WriteString(prefix + shown + "\n")
	}
}

// object decodes a JSON object into its members; anything else has none.
func object(value jsontext.Value) map[string]jsontext.Value {
	var members map[string]jsontext.Value
	if len(value) == 0 || jsonv2.Unmarshal(value, &members) != nil {
		return nil
	}
	return members
}

func text(value jsontext.Value) (string, bool) {
	var s string
	return s, len(value) > 0 && jsonv2.Unmarshal(value, &s) == nil
}

// canonical returns a value in the canonical form fingerprints use: keys
// sorted, strings by their text, and numbers exactly as written, so values
// compare equal exactly when they would fingerprint alike.
func canonical(value jsontext.Value) string {
	if len(value) == 0 {
		return ""
	}
	out, err := policy.Canonical(value)
	if err != nil {
		return string(value)
	}
	return out
}

// indented returns a value as indented JSON, made visible. Strings are
// written out decoded, so a character the upstream escaped is marked like one
// it did not.
func indented(value jsontext.Value) string {
	var out bytes.Buffer
	dec := jsontext.NewDecoder(bytes.NewReader(value))
	enc := jsontext.NewEncoder(&out, jsontext.WithIndent("  "), jsontext.EscapeForHTML(false), jsontext.EscapeForJS(false))
	for {
		token, err := dec.ReadToken()
		if err == io.EOF {
			break
		}
		if err != nil || enc.WriteToken(token) != nil {
			out.Reset()
			out.Write(value)
			break
		}
	}
	shown, _, _ := visible(out.String())
	return shown
}

// hidden counts the invisible and look-alike characters in every string and
// member name of a JSON value.
func hidden(value jsontext.Value) (invisible, lookAlike int) {
	dec := jsontext.NewDecoder(bytes.NewReader(value))
	for {
		token, err := dec.ReadToken()
		if err != nil {
			return invisible, lookAlike
		}
		if token.Kind() == '"' {
			_, i, l := visible(token.String())
			invisible, lookAlike = invisible+i, lookAlike+l
		}
	}
}

// definitionDiff describes, in labelled lines, how a proposed tool
// definition differs from the approved one: its description, parameters
// added or removed, changed parameter types and descriptions, required
// parameters, annotations, and any other field. _meta is not reviewed, as it
// is not part of a definition's fingerprint.
func definitionDiff(approved, proposed jsontext.Value) string {
	var b strings.Builder
	before, after := object(approved), object(proposed)
	keys := unionKeys(before, after)
	for _, key := range keys {
		if key == "_meta" || key == "name" || canonical(before[key]) == canonical(after[key]) {
			continue
		}
		switch key {
		case "description":
			old, _ := text(before[key])
			new, _ := text(after[key])
			b.WriteString("Description changed:\n")
			lineDiff(&b, old, new)
		case "inputSchema":
			schemaDiff(&b, before[key], after[key])
		case "annotations":
			old, new := object(before[key]), object(after[key])
			for _, name := range unionKeys(old, new) {
				if canonical(old[name]) != canonical(new[name]) {
					fmt.Fprintf(&b, "Annotation %s changed: %s → %s (revisit the tool's facts)\n", shownName(name), shownValue(old[name]), shownValue(new[name]))
				}
			}
		default:
			fmt.Fprintf(&b, "Field %s changed: %s → %s\n", shownName(key), shownValue(before[key]), shownValue(after[key]))
		}
	}
	return b.String()
}

func schemaDiff(b *strings.Builder, approved, proposed jsontext.Value) {
	before, after := object(approved), object(proposed)
	if before == nil || after == nil {
		fmt.Fprintf(b, "Input schema changed: %s → %s\n", shownValue(approved), shownValue(proposed))
		return
	}
	oldParams, newParams := object(before["properties"]), object(after["properties"])
	for _, name := range unionKeys(oldParams, newParams) {
		old, new := oldParams[name], newParams[name]
		switch {
		case old == nil:
			fmt.Fprintf(b, "Parameter added: %s %s\n", shownName(name), shownValue(new))
		case new == nil:
			fmt.Fprintf(b, "Parameter removed: %s\n", shownName(name))
		case canonical(old) != canonical(new):
			oldFields, newFields := object(old), object(new)
			if oldFields == nil || newFields == nil {
				// A schema can be true or false rather than an object.
				fmt.Fprintf(b, "Schema of parameter %s changed: %s → %s\n", shownName(name), shownValue(old), shownValue(new))
				continue
			}
			for _, field := range unionKeys(oldFields, newFields) {
				if canonical(oldFields[field]) == canonical(newFields[field]) {
					continue
				}
				switch field {
				case "type":
					fmt.Fprintf(b, "Type of parameter %s changed: %s → %s\n", shownName(name), shownValue(oldFields[field]), shownValue(newFields[field]))
				case "description":
					oldText, _ := text(oldFields[field])
					newText, _ := text(newFields[field])
					fmt.Fprintf(b, "Description of parameter %s changed:\n", shownName(name))
					lineDiff(b, oldText, newText)
				default:
					fmt.Fprintf(b, "Parameter %s field %s changed: %s → %s\n", shownName(name), shownName(field), shownValue(oldFields[field]), shownValue(newFields[field]))
				}
			}
		}
	}
	var oldRequired, newRequired []string
	_ = jsonv2.Unmarshal(before["required"], &oldRequired)
	_ = jsonv2.Unmarshal(after["required"], &newRequired)
	for _, name := range newRequired {
		if !slices.Contains(oldRequired, name) {
			fmt.Fprintf(b, "Parameter %s is now required\n", shownName(name))
		}
	}
	for _, name := range oldRequired {
		if !slices.Contains(newRequired, name) {
			fmt.Fprintf(b, "Parameter %s is no longer required\n", shownName(name))
		}
	}
	for _, key := range unionKeys(before, after) {
		if key != "properties" && key != "required" && canonical(before[key]) != canonical(after[key]) {
			fmt.Fprintf(b, "Input schema field %s changed: %s → %s\n", shownName(key), shownValue(before[key]), shownValue(after[key]))
		}
	}
}

func unionKeys(a, b map[string]jsontext.Value) []string {
	var keys []string
	for k := range a {
		keys = append(keys, k)
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	return keys
}

func shownName(name string) string { return visibleLine(name) }

func shownValue(value jsontext.Value) string {
	if len(value) == 0 {
		return "(none)"
	}
	return visibleLine(canonical(value))
}
