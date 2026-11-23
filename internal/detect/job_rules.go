package detect

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Mindburn-Labs/gatescan/internal/workflow"
)

// suppressedEvidence flags continue-on-error on a step that produces artifacts
// a later gate consumes: the evidence may be absent and the job still green.
func suppressedEvidence(job workflow.Job, facts []stepFacts) []Finding {
	var out []Finding
	for i, f := range facts {
		if !f.Step.ContinueOnError || len(f.Writes) == 0 {
			continue
		}
		for j := i + 1; j < len(facts); j++ {
			if facts[j].AssertionClass == "" {
				continue
			}
			shared := intersect(f.Writes, facts[j].Refs)
			if len(shared) == 0 {
				continue
			}
			out = append(out, Finding{
				Rule:     RuleSuppressed,
				Severity: SeverityHigh,
				Job:      job.ID,
				Step:     f.Step.Label(),
				Line:     f.Step.Line,
				Detail: fmt.Sprintf("continue-on-error: true on the step producing %s, which %q later validates",
					pathList(shared), facts[j].Step.Label()),
				Referent: "the producing step may fail silently, so the later check runs against whatever happens to be on disk",
			})
			break
		}
	}
	return out
}

var reNegativeCond = regexp.MustCompile(`(?:!=\s*'true'|==\s*'false'|!=\s*"true"|==\s*"false"|!\s*steps\.)`)

// fabricatedFallback flags a step that, on the branch where the real subject is
// missing, writes the artifact a later gate reads.
func fabricatedFallback(job workflow.Job, facts []stepFacts) []Finding {
	var out []Finding
	for i, f := range facts {
		if f.Step.If == "" || len(f.Writes) == 0 {
			continue
		}
		if !reNegativeCond.MatchString(f.Step.If) || !strings.Contains(f.Step.If, "steps.") {
			continue
		}
		for j := i + 1; j < len(facts); j++ {
			if facts[j].AssertionClass == "" {
				continue
			}
			shared := intersect(f.Writes, facts[j].Refs)
			if len(shared) == 0 {
				continue
			}
			out = append(out, Finding{
				Rule:     RuleFabricated,
				Severity: SeverityCritical,
				Job:      job.ID,
				Step:     f.Step.Label(),
				Line:     f.Step.Line,
				Detail: fmt.Sprintf("runs only when a prior detection step reported absence (if: %s) and then writes %s, which %q validates",
					strings.TrimSpace(f.Step.If), pathList(shared), facts[j].Step.Label()),
				Referent: "none — the branch that exists because the subject is missing supplies the evidence that the subject is fine",
			})
			break
		}
	}
	return out
}

// absenceReadsAsPass flags a glob iteration whose only failure path is inside
// the loop body, so zero matches means success.
func absenceReadsAsPass(job workflow.Job, facts []stepFacts) []Finding {
	var out []Finding
	for _, f := range facts {
		if f.AssertionClass == "" {
			continue
		}
		for _, g := range f.GlobLoops {
			if g.Guarded {
				continue
			}
			out = append(out, Finding{
				Rule:     RuleAbsencePass,
				Severity: SeverityHigh,
				Job:      job.ID,
				Step:     f.Step.Label(),
				Line:     f.Step.Line,
				Detail:   fmt.Sprintf("iterates %s and fails only from inside the loop, with no emptiness check before it", g.Glob),
				Referent: "none when the glob matches nothing — the step exits 0 and absence of evidence reads as evidence of compliance",
			})
		}
	}
	return out
}
