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

// reservedHosts are names standards guarantee never resolve to a real service.
// RFC 2606 documentation domains and reserved TLDs only.
//
// Loopback is deliberately absent. A CI job curling http://localhost:8080/health
// is smoke-testing a service it just started, which is a real referent; flagging
// it produced nothing but noise when this rule was first run against real
// pipelines.
var reservedHosts = []string{
	".example", ".invalid", ".test",
	"example.com", "example.net", "example.org",
}

// allowedSchemes name locations something can actually be fetched from. The
// list covers the package, registry, keyserver and database schemes real
// pipelines use, so the rule fires on invented ones rather than unfamiliar ones.
var allowedSchemes = map[string]bool{
	"http": true, "https": true, "ssh": true, "git": true, "file": true,
	"git+https": true, "git+ssh": true, "oci": true, "docker": true,
	"hkp": true, "hkps": true, "s3": true, "gs": true, "abfss": true,
	"postgres": true, "postgresql": true, "mysql": true, "redis": true,
	"amqp": true, "amqps": true, "mongodb": true, "grpc": true, "grpcs": true,
}

var reURLLit = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s"'` + "`" + `),]+`)

// syntheticAnchors flags evidence references that point somewhere nothing lives.
func syntheticAnchors(wf *workflow.Workflow, job workflow.Job, facts []stepFacts, env map[string]string) []Finding {
	seen := map[string]bool{}
	var out []Finding

	consider := func(step workflow.Step, text, context string) {
		bound := digestBoundStems(context)
		for _, lit := range reURLLit.FindAllString(text, -1) {
			expanded := workflow.ExpandRaw(lit, env)
			if seen[expanded] {
				continue
			}
			rule, sev, reason := anchorProblem(expanded)
			if reason == "" {
				continue
			}
			// A locator a stranger cannot follow is still sound evidence when
			// the same block binds a digest for the same subject: the reader
			// verifies the bytes they were handed rather than fetching them.
			// Verifiable matters; resolvable is a convenience.
			//
			// This never excuses a reserved documentation host. Digesting a
			// fabricated file proves the fabrication is intact, not that it
			// describes anything.
			if rule == RuleUnresolvable {
				if stem := anchorStem(text, lit); stem != "" && bound[stem] {
					continue
				}
			}
			seen[expanded] = true
			line := wf.LineOfFrom(strings.SplitN(lit, "$", 2)[0], step.Line)
			if line == 0 {
				line = step.Line
			}
			referent := "none — an anchor that resolves nowhere records the shape of proof without its substance"
			if rule == RuleUnresolvable {
				referent = "unknown — whether this resolves depends on a convention outside the workflow, so a reader cannot tell proof from its shape without being told"
			}
			out = append(out, Finding{
				Rule:     rule,
				Severity: sev,
				Job:      job.ID,
				Step:     step.Label(),
				Line:     line,
				Detail:   fmt.Sprintf("evidence reference %s %s", expanded, reason),
				Referent: referent,
			})
		}
	}

	for _, f := range facts {
		consider(f.Step, f.Step.Run, f.Step.Run)
		for _, v := range f.Step.Env {
			consider(f.Step, v, f.Step.Run+"\n"+v)
		}
		for _, v := range f.Step.With {
			consider(f.Step, v, f.Step.Run+"\n"+v)
		}
	}
	for _, v := range env {
		if len(job.Steps) > 0 {
			consider(job.Steps[0], v, v)
		}
	}
	return out
}

var (
	// A binding whose name ends in a digest-ish suffix pins content.
	reDigestBinding = regexp.MustCompile(`(?i)\b([A-Za-z_][A-Za-z0-9_]*?)_(?:digest|sha256|sha512|checksum)\b`)
	// The identifier immediately preceding a value carries it.
	reCarrierName = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)[^A-Za-z0-9_]*$`)
	// Suffixes that mark a name as a locator rather than the subject itself.
	refSuffixes = []string{"_ref", "_uri", "_url", "_link", "_path", "_location"}
)

// digestBoundStems collects the subjects the text binds a digest for, as
// lower-cased stems: "SBOM_DIGEST" and "sbom_digest: $x" both yield "sbom".
func digestBoundStems(text string) map[string]bool {
	out := map[string]bool{}
	for _, m := range reDigestBinding.FindAllStringSubmatch(text, -1) {
		out[strings.ToLower(m[1])] = true
	}
	return out
}

// anchorStem names the subject an anchor literal describes, by reading back to
// the identifier that carries it and dropping any locator suffix. It returns ""
// when no carrier is discernible, which leaves the finding standing — silence
// here must not suppress.
func anchorStem(text, literal string) string {
	i := strings.Index(text, literal)
	if i < 0 {
		return ""
	}
	const window = 96
	start := i - window
	if start < 0 {
		start = 0
	}
	m := reCarrierName.FindStringSubmatch(text[start:i])
	if m == nil {
		return ""
	}
	name := strings.ToLower(m[1])
	for _, suf := range refSuffixes {
		if strings.HasSuffix(name, suf) {
			return strings.TrimSuffix(name, suf)
		}
	}
	return ""
}

var reScheme = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9+.-]*)://`)

// anchorProblem classifies an evidence reference, returning the rule to raise,
// its severity, and a description — or an empty reason when the reference is
// fine.
//
// The two checks differ in how much they can prove, and saying so is the point:
//   - A reserved documentation host is fake by standard. No convention rescues
//     it, so it is reported as fact.
//   - An unrecognised scheme may be a perfectly good in-house locator. The
//     workflow cannot tell us, so it is raised for a human at medium and left
//     out of the default failure threshold. Over-claiming here would cost more
//     than the finding is worth.
func anchorProblem(raw string) (rule, severity, reason string) {
	m := reScheme.FindStringSubmatch(raw)
	if m == nil {
		return "", "", ""
	}
	scheme := strings.ToLower(m[1])

	// Scheme is readable even when the rest still holds an unexpanded variable,
	// so judge it first and never let a "${...}" silently skip the check.
	if !allowedSchemes[scheme] {
		return RuleUnresolvable, SeverityMedium,
			fmt.Sprintf("uses the non-standard %q scheme; a reader outside this pipeline cannot resolve it", scheme)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", "", ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", "", ""
	}
	for _, r := range reservedHosts {
		if host == strings.TrimPrefix(r, ".") || strings.HasSuffix(host, r) {
			return RuleSyntheticAnchor, SeverityHigh,
				fmt.Sprintf("resolves to the reserved host %q, which by standard never hosts a real service", host)
		}
	}
	return "", "", ""
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
