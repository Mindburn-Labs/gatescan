// Package workflow parses GitHub Actions workflow files into a model that
// keeps source line numbers, so every finding can cite file:line.
//
// It walks the yaml.Node tree rather than decoding into structs. That costs a
// little more code and buys two things: line numbers for free, and immunity to
// the YAML 1.1 "Norway problem" — the `on:` key resolves to a boolean under
// some schemas, but a key node keeps its literal source text either way.
package workflow

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Workflow is one parsed workflow file.
type Workflow struct {
	Path     string            `json:"path"`
	Name     string            `json:"name,omitempty"`
	Triggers []Trigger         `json:"triggers,omitempty"`
	Env      map[string]string `json:"-"`
	Jobs     []Job             `json:"jobs"`

	// Lines is the raw file split on newlines, so a finding about a literal
	// can cite the line it actually sits on.
	Lines []string `json:"-"`
}

// LineOf returns the 1-based line on which literal first appears, or 0.
func (w *Workflow) LineOf(literal string) int {
	for i, l := range w.Lines {
		if strings.Contains(l, literal) {
			return i + 1
		}
	}
	return 0
}

// Trigger is one entry under `on:`, with its path filter if it has one.
type Trigger struct {
	Event string   `json:"event"`
	Paths []string `json:"paths,omitempty"`
	Line  int      `json:"line"`
}

// Job is one entry under `jobs:`.
type Job struct {
	ID    string            `json:"id"`
	Name  string            `json:"name,omitempty"`
	Line  int               `json:"line"`
	Env   map[string]string `json:"-"`
	Steps []Step            `json:"steps"`
}

// Step is one entry under a job's `steps:`.
type Step struct {
	Index           int               `json:"index"`
	Name            string            `json:"name,omitempty"`
	ID              string            `json:"id,omitempty"`
	If              string            `json:"if,omitempty"`
	Uses            string            `json:"uses,omitempty"`
	Run             string            `json:"run,omitempty"`
	With            map[string]string `json:"-"`
	Env             map[string]string `json:"-"`
	ContinueOnError bool              `json:"continue_on_error,omitempty"`
	Line            int               `json:"line"`
}

// Label names a step for a finding: its name if it has one, else its position.
func (s Step) Label() string {
	if s.Name != "" {
		return s.Name
	}
	if s.Uses != "" {
		return "uses: " + s.Uses
	}
	return fmt.Sprintf("step #%d", s.Index+1)
}

// ParseFile reads and parses one workflow file.
func ParseFile(path string) (*Workflow, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(path, raw)
}

// Parse parses workflow bytes. path is recorded for citations only.
func Parse(path string, raw []byte) (*Workflow, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	root := documentRoot(&doc)
	if root == nil || root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: not a workflow mapping", path)
	}

	wf := &Workflow{
		Path: path,
		Name: scalar(mapGet(root, "name")),
		Env:  stringMap(mapGet(root, "env")),
	}
	wf.Lines = strings.Split(string(raw), "\n")
	wf.Triggers = parseTriggers(mapGet(root, "on"))
	wf.Jobs = parseJobs(mapGet(root, "jobs"))
	return wf, nil
}

func documentRoot(n *yaml.Node) *yaml.Node {
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		return n.Content[0]
	}
	return n
}

// mapGet returns the value node for key in a mapping node, comparing the key's
// literal source text. That keeps `on:` addressable even when a YAML schema
// resolves it to a boolean.
func mapGet(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func scalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

func stringMap(n *yaml.Node) map[string]string {
	out := map[string]string{}
	if n == nil || n.Kind != yaml.MappingNode {
		return out
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i+1].Kind == yaml.ScalarNode {
			out[n.Content[i].Value] = n.Content[i+1].Value
		}
	}
	return out
}

func stringList(n *yaml.Node) []string {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.ScalarNode {
		return []string{n.Value}
	}
	if n.Kind != yaml.SequenceNode {
		return nil
	}
	out := make([]string, 0, len(n.Content))
	for _, c := range n.Content {
		if c.Kind == yaml.ScalarNode {
			out = append(out, c.Value)
		}
	}
	return out
}

func parseTriggers(on *yaml.Node) []Trigger {
	if on == nil {
		return nil
	}
	switch on.Kind {
	case yaml.ScalarNode:
		return []Trigger{{Event: on.Value, Line: on.Line}}
	case yaml.SequenceNode:
		out := make([]Trigger, 0, len(on.Content))
		for _, c := range on.Content {
			out = append(out, Trigger{Event: c.Value, Line: c.Line})
		}
		return out
	case yaml.MappingNode:
		out := make([]Trigger, 0, len(on.Content)/2)
		for i := 0; i+1 < len(on.Content); i += 2 {
			k, v := on.Content[i], on.Content[i+1]
			t := Trigger{Event: k.Value, Line: k.Line}
			if v.Kind == yaml.MappingNode {
				t.Paths = stringList(mapGet(v, "paths"))
			}
			out = append(out, t)
		}
		return out
	}
	return nil
}

func parseJobs(jobs *yaml.Node) []Job {
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return nil
	}
	out := make([]Job, 0, len(jobs.Content)/2)
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		k, v := jobs.Content[i], jobs.Content[i+1]
		j := Job{ID: k.Value, Line: k.Line}
		if v.Kind == yaml.MappingNode {
			j.Name = scalar(mapGet(v, "name"))
			j.Env = stringMap(mapGet(v, "env"))
			j.Steps = parseSteps(mapGet(v, "steps"))
		}
		out = append(out, j)
	}
	return out
}

func parseSteps(steps *yaml.Node) []Step {
	if steps == nil || steps.Kind != yaml.SequenceNode {
		return nil
	}
	out := make([]Step, 0, len(steps.Content))
	for i, c := range steps.Content {
		s := Step{Index: i, Line: c.Line}
		if c.Kind == yaml.MappingNode {
			s.Name = scalar(mapGet(c, "name"))
			s.ID = scalar(mapGet(c, "id"))
			s.If = scalar(mapGet(c, "if"))
			s.Uses = scalar(mapGet(c, "uses"))
			s.Run = scalar(mapGet(c, "run"))
			s.With = stringMap(mapGet(c, "with"))
			s.Env = stringMap(mapGet(c, "env"))
			s.ContinueOnError = scalar(mapGet(c, "continue-on-error")) == "true"
		}
		out = append(out, s)
	}
	return out
}

// ---- environment resolution -------------------------------------------------

var (
	exprRe    = regexp.MustCompile(`\$\{\{[^}]*\}\}`)
	braceVar  = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
	plainVar  = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)`)
	exprInner = regexp.MustCompile(`\$\{\{\s*(.*?)\s*\}\}`)
	workspace = regexp.MustCompile(`\$\{\{\s*github\.workspace\s*\}\}/?`)
)

// JobEnv merges workflow-level and job-level env, job winning, then resolves
// each value against the merged set so entries defined in terms of each other
// (the common CI_ARTIFACT_DIR / RESULT_JSON pattern) come out fully expanded.
func (w *Workflow) JobEnv(j Job) map[string]string {
	merged := map[string]string{}
	for k, v := range w.Env {
		merged[k] = v
	}
	for k, v := range j.Env {
		merged[k] = v
	}
	resolved := make(map[string]string, len(merged))
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic output regardless of map order
	for _, k := range keys {
		resolved[k] = Expand(merged[k], merged)
	}
	return resolved
}

// Expand resolves a shell-ish string into a comparable canonical path.
//
// Workflow expressions become stable placeholders rather than being dropped:
// `${{ github.workspace }}` is elided (it is the working directory root), and
// any other `${{ x }}` becomes `<x>` so two references to the same run id
// compare equal while different expressions stay distinct.
//
// ponytail: substitution is bounded to a fixed number of passes rather than
// tracking a resolution graph. Raise the bound if real workflows nest deeper.
func Expand(s string, env map[string]string) string {
	return normalizePath(ExpandRaw(s, env))
}

// ExpandRaw performs the same substitution as Expand without collapsing path
// separators. URLs must go through this one: normalising "//" would turn
// "https://host/x" into "https:/host/x" and lose the host entirely.
func ExpandRaw(s string, env map[string]string) string {
	const maxPasses = 8
	for pass := 0; pass < maxPasses; pass++ {
		before := s
		s = workspace.ReplaceAllString(s, "")
		s = exprInner.ReplaceAllStringFunc(s, func(m string) string {
			inner := strings.TrimSpace(exprInner.FindStringSubmatch(m)[1])
			return "<" + inner + ">"
		})
		s = braceVar.ReplaceAllStringFunc(s, func(m string) string {
			name := braceVar.FindStringSubmatch(m)[1]
			if v, ok := env[name]; ok {
				return v
			}
			return m
		})
		s = plainVar.ReplaceAllStringFunc(s, func(m string) string {
			name := plainVar.FindStringSubmatch(m)[1]
			if v, ok := env[name]; ok {
				return v
			}
			return m
		})
		if s == before {
			break
		}
	}
	return s
}

// normalizePath collapses the cosmetic differences between two spellings of
// the same location so path comparison is about the location, not the quoting.
func normalizePath(s string) string {
	s = strings.Trim(s, `"'`)
	s = strings.ReplaceAll(s, `\`, "")
	for strings.Contains(s, "//") {
		s = strings.ReplaceAll(s, "//", "/")
	}
	s = strings.TrimPrefix(s, "./")
	return strings.TrimSuffix(s, "/")
}

// HasExpr reports whether s still contains an unresolved workflow expression.
func HasExpr(s string) bool { return exprRe.MatchString(s) }
