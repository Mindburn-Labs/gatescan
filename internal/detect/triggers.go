package detect

import (
	"fmt"
	"strings"

	"github.com/Mindburn-Labs/gatescan/internal/workflow"
)

// unreachableSubject flags path filters naming paths the repository excludes,
// so the workflow can never be triggered by a change to its stated subject.
func unreachableSubject(wf *workflow.Workflow, opts Options) ([]Finding, []string) {
	if opts.GitIgnored == nil {
		return nil, []string{RuleUnreachable + ": no repository context supplied (-repo), rule not evaluated"}
	}
	var out []Finding
	seen := map[string]bool{}
	for _, t := range wf.Triggers {
		for _, p := range t.Paths {
			base := globPrefix(p)
			if base == "" || seen[base] {
				continue
			}
			seen[base] = true
			if strings.HasPrefix(base, ".github/") {
				continue // the workflow watching itself is normal
			}
			exists := opts.PathExists != nil && opts.PathExists(base)
			if exists || !opts.GitIgnored(base) {
				continue
			}
			out = append(out, Finding{
				Rule:     RuleUnreachable,
				Severity: SeverityCritical,
				Line:     t.Line,
				Detail: fmt.Sprintf("trigger %q filters on %q, but %q is absent from the repository and excluded by .gitignore",
					t.Event, p, base),
				Referent: "none — no commit can ever match this filter, so the gate never runs against the subject it names",
			})
		}
	}
	return out, nil
}

// globPrefix is the literal directory portion of a path filter.
func globPrefix(p string) string {
	if i := strings.IndexAny(p, "*?["); i >= 0 {
		p = p[:i]
	}
	return strings.TrimSuffix(strings.TrimSpace(p), "/")
}
