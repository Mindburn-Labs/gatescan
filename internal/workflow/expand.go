package workflow

import (
	"regexp"
	"sort"
	"strings"
)

var (
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
func Expand(s string, env map[string]string) string {
	return normalizePath(ExpandRaw(s, env))
}

// ExpandRaw performs the same substitution as Expand without collapsing path
// separators. Use it for URLs so the scheme and host stay intact. Expansion
// limits the number of substitution passes to bound work on cyclic references.
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
