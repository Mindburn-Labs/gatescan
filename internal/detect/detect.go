// Package detect examines GitHub Actions checks and identifies where their inputs
// come from. The rules flag patterns that weaken a gate's evidence.
package detect

import (
	"fmt"
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
	RuleUnresolvable    = "unresolvable_anchor"
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
	// VerdictUnanalysed is not a judgement about the gate. It says the shell
	// was too opaque to name the checks' inputs, and reporting that plainly is
	// the only honest option — the alternative is exactly the defect this tool
	// exists to find, absence of evidence rendered as a conclusion.
	VerdictUnanalysed = "INPUTS_NOT_IDENTIFIED"
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
	Class    string   `json:"class"`
	Internal []string `json:"internal_inputs,omitempty"`
	External []string `json:"external_inputs,omitempty"`
}

// analysed reports whether any input was identified at all. A check with none
// was not judged; it was not read.
func (a Assertion) analysed() bool { return len(a.Internal)+len(a.External) > 0 }

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
	// Acceptances are human decisions to tolerate specific findings.
	Acceptances []Acceptance
}

// Result is everything gatescan concluded about one workflow file.
type Result struct {
	Path     string      `json:"path"`
	Name     string      `json:"name,omitempty"`
	Jobs     []JobResult `json:"jobs"`
	Findings []Finding   `json:"findings"`
	Skipped  []string    `json:"skipped_rules,omitempty"`
	// Accepted are findings a human decided to tolerate, kept visible with the
	// decision attached rather than dropped.
	Accepted []Accepted `json:"accepted,omitempty"`
	// StaleAcceptances name sign-offs that no longer cover anything.
	StaleAcceptances []string `json:"stale_acceptances,omitempty"`
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
	applyAcceptances(res, opts.Acceptances)
	return res
}

// assessJob splits every gate step's inputs into internal and external, and
// raises self_referential_evidence for the gates with no external input at all.
func assessJob(job workflow.Job, facts []stepFacts) ([]Assertion, []Finding) {
	var assertions []Assertion
	var findings []Finding

	derived := derivedProducers(facts)

	for i, f := range facts {
		if f.AssertionClass == "" {
			continue
		}
		produced := producedBefore(facts, i)
		self := map[string]bool{}
		for _, w := range f.Writes {
			self[w] = true
		}

		a := Assertion{Step: f.Step.Label(), Line: f.Step.Line, Class: f.AssertionClass}
		a.External = append(a.External, f.External...)
		sources := map[string]string{}
		for _, ref := range f.Refs {
			if self[ref] {
				continue // the step's own scratch output is not an input
			}
			if o, ok := coveredBy(produced, ref); ok {
				if derived[o.Step] && !o.ViaMkdir {
					// Output of a compiler or test runner over repository
					// source: the referent is that source, one hop away and
					// out of reach of static shell reading. Creating the
					// directory does not confer this — only writing the file.
					a.External = append(a.External, "derived:"+o.Step)
					continue
				}
				a.Internal = append(a.Internal, ref)
				sources[ref] = o.Step
			} else {
				a.External = append(a.External, ref)
			}
		}
		sort.Strings(a.Internal)
		sort.Strings(a.External)

		if len(a.Internal) > 0 && len(a.External) == 0 {
			sev, referent := SeverityCritical,
				"none — this check compares the job's output against the job's output, so it cannot fail"
			if distinctValues(sources) > 1 {
				// Two steps producing independently and then compared is the
				// reproducible-build idiom, where disagreement is the signal.
				// It is vacuous only when both outputs derive from one source.
				sev = SeverityHigh
				referent = "only disagreement between this job's own steps — sound for a replication check whose two outputs were produced independently, vacuous when both derive from a single source"
			}
			findings = append(findings, Finding{
				Rule:     RuleSelfReferential,
				Severity: sev,
				Job:      job.ID,
				Step:     f.Step.Label(),
				Line:     f.Step.Line,
				Detail: fmt.Sprintf("validates %s, every one of which was written earlier in this same job (%s)",
					pathList(a.Internal), sourceList(a.Internal, sources)),
				Referent: referent,
			})
		}
		assertions = append(assertions, a)
	}
	return assertions, findings
}

// derivedProducers maps a step label to whether that step built its output
// from repository source with a toolchain.
func derivedProducers(facts []stepFacts) map[string]bool {
	out := map[string]bool{}
	for _, f := range facts {
		if f.Derives {
			out[f.Step.Label()] = true
		}
	}
	return out
}

func distinctValues(m map[string]string) int {
	seen := map[string]bool{}
	for _, v := range m {
		seen[v] = true
	}
	return len(seen)
}

func verdict(as []Assertion) string {
	if len(as) == 0 {
		return VerdictNoAssertion
	}
	analysed, withExternal := 0, 0
	for _, a := range as {
		if !a.analysed() {
			continue
		}
		analysed++
		if len(a.External) > 0 {
			withExternal++
		}
	}
	switch {
	case analysed == 0:
		// Every check was opaque. Saying ESTABLISHES_NOTHING here would be a
		// conclusion drawn from having seen nothing.
		return VerdictUnanalysed
	case withExternal == 0:
		return VerdictNothing
	case withExternal < analysed:
		return VerdictPartial
	default:
		return VerdictEstablishes
	}
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
