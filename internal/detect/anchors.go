package detect

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/Mindburn-Labs/gatescan/internal/workflow"
)

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
