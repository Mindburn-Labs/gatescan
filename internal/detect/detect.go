// Package detect answers one question about a CI gate: what external referent
// could make it fail?
//
// A check whose every input was produced by the same job moments earlier is
// not a check. It is a tautology with ceremony around it, and it reports green
// for the same reason a mirror agrees with you. The rules here find the shapes
// that produce that outcome.
package detect

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/Mindburn-Labs/gatescan/internal/workflow"
)

// Severity ranks a finding by what it costs the reader to be wrong about it.
const (
	SeverityCritical = "critical" // the gate cannot fail
	SeverityHigh     = "high"     // the gate can fail, but not for the stated reason
	SeverityMedium   = "medium"   // the gate's evidence is weaker than it appears
)

// Rule identifiers. Stable strings: they end up in report.json.
const (
	RuleSelfReferential = "self_referential_evidence"
	RuleSyntheticAnchor = "synthetic_anchor"
	RuleUnreachable     = "unreachable_subject"
	RuleFabricated      = "fabricated_fallback"
	RuleSuppressed      = "suppressed_evidence_step"
	RuleAbsencePass     = "absence_reads_as_pass"
)

// Job verdicts.
const (
	VerdictEstablishes = "ESTABLISHES"
	VerdictPartial     = "PARTIAL"
	VerdictNothing     = "ESTABLISHES_NOTHING"
	VerdictNoAssertion = "NO_ASSERTIONS"
)

// Finding is one observation, citable at file:line.
type Finding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Job      string `json:"job,omitempty"`
	Step     string `json:"step,omitempty"`
	Line     int    `json:"line,omitempty"`
	Detail   string `json:"detail"`
	Referent string `json:"referent"`
}

// Assertion records one gate step and where its inputs came from.
type Assertion struct {
	Step     string   `json:"step"`
	Line     int      `json:"line"`
	Internal []string `json:"internal_inputs,omitempty"`
	External []string `json:"external_inputs,omitempty"`
}

// JobResult is the per-job verdict and its supporting findings.
type JobResult struct {
	ID         string      `json:"id"`
	Name       string      `json:"name,omitempty"`
	Line       int         `json:"line"`
	Verdict    string      `json:"verdict"`
	Assertions []Assertion `json:"assertions,omitempty"`
	Findings   []Finding   `json:"findings,omitempty"`
}

// Options carries the context a rule needs from outside the workflow file.
type Options struct {
	// GitIgnored reports whether a repo-relative path is excluded from the
	// repository. Nil disables the unreachable-subject rule, which then
	// records why it was skipped rather than silently passing.
	GitIgnored func(path string) bool
	// PathExists reports whether a repo-relative path is present on disk.
	PathExists func(path string) bool
}

// Result is everything gatescan concluded about one workflow file.
type Result struct {
	Path     string      `json:"path"`
	Name     string      `json:"name,omitempty"`
	Jobs     []JobResult `json:"jobs"`
	Findings []Finding   `json:"findings"`
	Skipped  []string    `json:"skipped_rules,omitempty"`
}

// Run applies every rule to one parsed workflow.
func Run(wf *workflow.Workflow, opts Options) *Result {
	// Non-nil slices: report.json consumers should see [] for "nothing found",
	// never null, so an empty result is distinguishable from a missing field.
	res := &Result{Path: wf.Path, Name: wf.Name, Jobs: []JobResult{}, Findings: []Finding{}}

	for _, job := range wf.Jobs {
		env := wf.JobEnv(job)
		facts := make([]stepFacts, 0, len(job.Steps))
		for _, s := range job.Steps {
			facts = append(facts, analyzeStep(s, env))
		}

		jr := JobResult{ID: job.ID, Name: job.Name, Line: job.Line, Findings: []Finding{}}
		jr.Assertions, jr.Findings = assessJob(job, facts)
		jr.Findings = append(jr.Findings, suppressedEvidence(job, facts)...)
		jr.Findings = append(jr.Findings, fabricatedFallback(job, facts)...)
		jr.Findings = append(jr.Findings, absenceReadsAsPass(job, facts)...)
		jr.Findings = append(jr.Findings, syntheticAnchors(wf, job, facts, env)...)
		jr.Verdict = verdict(jr.Assertions)

		sortFindings(jr.Findings)
		res.Jobs = append(res.Jobs, jr)
		res.Findings = append(res.Findings, jr.Findings...)
	}

	unreachable, skipped := unreachableSubject(wf, opts)
	res.Findings = append(res.Findings, unreachable...)
	res.Skipped = skipped

	sortFindings(res.Findings)
	return res
}

// assessJob splits every gate step's inputs into internal and external, and
// raises self_referential_evidence for the gates with no external input at all.
func assessJob(job workflow.Job, facts []stepFacts) ([]Assertion, []Finding) {
	var assertions []Assertion
	var findings []Finding

	for i, f := range facts {
		if !f.Gate {
			continue
		}
		produced := producedBefore(facts, i)
		self := map[string]bool{}
		for _, w := range f.Writes {
			self[w] = true
		}

		a := Assertion{Step: f.Step.Label(), Line: f.Step.Line}
		sources := map[string]string{}
		for _, ref := range f.Refs {
			if self[ref] {
				continue // the step's own scratch output is not an input
			}
			if src, ok := coveredBy(produced, ref); ok {
				a.Internal = append(a.Internal, ref)
				sources[ref] = src
			} else {
				a.External = append(a.External, ref)
			}
		}
		sort.Strings(a.Internal)
		sort.Strings(a.External)

		if len(a.Internal) > 0 && len(a.External) == 0 {
			findings = append(findings, Finding{
				Rule:     RuleSelfReferential,
				Severity: SeverityCritical,
				Job:      job.ID,
				Step:     f.Step.Label(),
				Line:     f.Step.Line,
				Detail: fmt.Sprintf("validates %s, every one of which was written earlier in this same job (%s)",
					pathList(a.Internal), sourceList(a.Internal, sources)),
				Referent: "none — this check compares the job's output against the job's output, so it cannot fail",
			})
		}
		assertions = append(assertions, a)
	}
	return assertions, findings
}

func verdict(as []Assertion) string {
	if len(as) == 0 {
		return VerdictNoAssertion
	}
	withExternal := 0
	for _, a := range as {
		if len(a.External) > 0 {
			withExternal++
		}
	}
	switch {
	case withExternal == 0:
		return VerdictNothing
	case withExternal < len(as):
		return VerdictPartial
	default:
		return VerdictEstablishes
	}
}

// suppressedEvidence flags continue-on-error on a step that produces artifacts
// a later gate consumes: the evidence may be absent and the job still green.
func suppressedEvidence(job workflow.Job, facts []stepFacts) []Finding {
	var out []Finding
	for i, f := range facts {
		if !f.Step.ContinueOnError || len(f.Writes) == 0 {
			continue
		}
		for j := i + 1; j < len(facts); j++ {
			if !facts[j].Gate {
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
			if !facts[j].Gate {
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
		if !f.Gate {
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

// reservedHosts are names guaranteed never to resolve to a real service:
// RFC 2606 reserved TLDs and second-level names, plus RFC 6761 special use.
var reservedHosts = []string{
	".example", ".invalid", ".test", ".localhost", ".local",
	"example.com", "example.net", "example.org",
	"localhost", "127.0.0.1", "0.0.0.0", "::1",
}

var allowedSchemes = map[string]bool{
	"http": true, "https": true, "ssh": true, "git": true, "file": true,
}

var reURLLit = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s"'` + "`" + `),]+`)

// syntheticAnchors flags evidence references that point somewhere nothing lives.
func syntheticAnchors(wf *workflow.Workflow, job workflow.Job, facts []stepFacts, env map[string]string) []Finding {
	seen := map[string]bool{}
	var out []Finding

	consider := func(step workflow.Step, text string) {
		for _, lit := range reURLLit.FindAllString(text, -1) {
			expanded := workflow.ExpandRaw(lit, env)
			if seen[expanded] {
				continue
			}
			reason := anchorProblem(expanded)
			if reason == "" {
				continue
			}
			seen[expanded] = true
			line := wf.LineOf(strings.SplitN(lit, "$", 2)[0])
			if line == 0 {
				line = step.Line
			}
			out = append(out, Finding{
				Rule:     RuleSyntheticAnchor,
				Severity: SeverityHigh,
				Job:      job.ID,
				Step:     step.Label(),
				Line:     line,
				Detail:   fmt.Sprintf("evidence reference %s %s", expanded, reason),
				Referent: "none — an anchor that resolves nowhere records the shape of proof without its substance",
			})
		}
	}

	for _, f := range facts {
		consider(f.Step, f.Step.Run)
		for _, v := range f.Step.Env {
			consider(f.Step, v)
		}
		for _, v := range f.Step.With {
			consider(f.Step, v)
		}
	}
	for _, v := range env {
		if len(job.Steps) > 0 {
			consider(job.Steps[0], v)
		}
	}
	return out
}

func anchorProblem(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if !allowedSchemes[u.Scheme] {
		return fmt.Sprintf("uses the %q scheme, which names no retrievable location", u.Scheme)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ""
	}
	for _, r := range reservedHosts {
		if host == strings.TrimPrefix(r, ".") || strings.HasSuffix(host, r) {
			return fmt.Sprintf("resolves to the reserved host %q, which by standard never hosts a real service", host)
		}
	}
	return ""
}

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

func intersect(a, b []string) []string {
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	var out []string
	for _, y := range b {
		if set[y] {
			out = append(out, y)
		}
	}
	sort.Strings(out)
	return out
}

func pathList(xs []string) string {
	if len(xs) == 1 {
		return xs[0]
	}
	if len(xs) <= 3 {
		return strings.Join(xs, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(xs[:3], ", "), len(xs)-3)
}

func sourceList(refs []string, sources map[string]string) string {
	seen := map[string]bool{}
	var names []string
	for _, r := range refs {
		if s := sources[r]; s != "" && !seen[s] {
			seen[s] = true
			names = append(names, fmt.Sprintf("%q", s))
		}
	}
	sort.Strings(names)
	if len(names) > 2 {
		names = append(names[:2], fmt.Sprintf("and %d more steps", len(names)-2))
	}
	return strings.Join(names, ", ")
}

var severityRank = map[string]int{SeverityCritical: 0, SeverityHigh: 1, SeverityMedium: 2}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if severityRank[fs[i].Severity] != severityRank[fs[j].Severity] {
			return severityRank[fs[i].Severity] < severityRank[fs[j].Severity]
		}
		if fs[i].Line != fs[j].Line {
			return fs[i].Line < fs[j].Line
		}
		return fs[i].Rule < fs[j].Rule
	})
}
