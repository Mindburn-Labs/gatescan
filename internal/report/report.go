// Package report renders scan results: a terminal table, a machine-readable
// report.json, and a single self-contained report.html.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mindburn-Labs/gatescan/internal/detect"
)

// Version is the tool version stamped into every report.
const Version = "0.1.0-prototype"

// Report is the whole output of one scan.
type Report struct {
	Tool      string           `json:"tool"`
	Version   string           `json:"version"`
	ScannedAt time.Time        `json:"scanned_at"`
	Subject   string           `json:"subject"`
	Question  string           `json:"question"`
	Summary   Summary          `json:"summary"`
	Workflows []*detect.Result `json:"workflows"`
}

// Summary is the headline count set.
type Summary struct {
	Workflows            int            `json:"workflows"`
	Jobs                 int            `json:"jobs"`
	Findings             int            `json:"findings"`
	BySeverity           map[string]int `json:"by_severity"`
	ByRule               map[string]int `json:"by_rule"`
	JobsEstablishNothing int            `json:"jobs_establishing_nothing"`
	JobsUnanalysed       int            `json:"jobs_inputs_not_identified"`
}

// Build assembles a report from per-workflow results.
func Build(subject string, results []*detect.Result, now time.Time) *Report {
	r := &Report{
		Tool:      "gatescan",
		Version:   Version,
		ScannedAt: now.UTC(),
		Subject:   subject,
		Question:  "For each check in these workflows: what external referent could make it fail?",
		Workflows: results,
		Summary: Summary{
			Workflows:  len(results),
			BySeverity: map[string]int{},
			ByRule:     map[string]int{},
		},
	}
	for _, res := range results {
		r.Summary.Jobs += len(res.Jobs)
		for _, j := range res.Jobs {
			switch j.Verdict {
			case detect.VerdictNothing:
				r.Summary.JobsEstablishNothing++
			case detect.VerdictUnanalysed:
				r.Summary.JobsUnanalysed++
			}
		}
		for _, f := range res.Findings {
			r.Summary.Findings++
			r.Summary.BySeverity[f.Severity]++
			r.Summary.ByRule[f.Rule]++
		}
	}
	return r
}

// Clean reports whether the scan found nothing.
func (r *Report) Clean() bool { return r.Summary.Findings == 0 }

// WriteJSON writes report.json into dir.
func WriteJSON(r *Report, dir string) (string, error) {
	path := filepath.Join(dir, "report.json")
	buf, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return path, os.WriteFile(path, append(buf, '\n'), 0o644)
}

var verdictGloss = map[string]string{
	detect.VerdictEstablishes: "every check has at least one input it did not produce",
	detect.VerdictPartial:     "some checks rest entirely on inputs this job produced",
	detect.VerdictNothing:     "every check rests entirely on inputs this job produced",
	detect.VerdictNoAssertion: "no step in this job can fail the run",
	detect.VerdictUnanalysed:  "this job's checks were too opaque to read; not a verdict on the gate",
}

// Terminal prints a human-readable summary.
func Terminal(w io.Writer, r *Report) {
	fmt.Fprintf(w, "gatescan %s — offline gate admissibility scan\n", r.Version)
	fmt.Fprintf(w, "subject: %s\n", r.Subject)
	fmt.Fprintf(w, "question: %s\n\n", r.Question)

	for _, res := range r.Workflows {
		title := res.Name
		if title == "" {
			title = filepath.Base(res.Path)
		}
		fmt.Fprintf(w, "%s  (%s)\n", title, res.Path)
		for _, j := range res.Jobs {
			fmt.Fprintf(w, "  job %-28s %-20s %s\n", j.ID, j.Verdict, verdictGloss[j.Verdict])
			for _, a := range j.Assertions {
				fmt.Fprintf(w, "      check %q\n", a.Step)
				fmt.Fprintf(w, "          external inputs: %s\n", countOrNone(a.External))
				fmt.Fprintf(w, "          internal inputs: %s\n", countOrNone(a.Internal))
			}
		}
		if len(res.Findings) == 0 {
			fmt.Fprintf(w, "  no findings\n")
		}
		for _, f := range res.Findings {
			fmt.Fprintf(w, "\n  [%s] %s\n", strings.ToUpper(f.Severity), f.Rule)
			if f.Step != "" {
				fmt.Fprintf(w, "      step: %s\n", f.Step)
			}
			fmt.Fprintf(w, "      at:   %s:%d\n", res.Path, f.Line)
			fmt.Fprintf(w, "      what: %s\n", f.Detail)
			fmt.Fprintf(w, "      referent: %s\n", f.Referent)
		}
		for _, s := range res.Skipped {
			fmt.Fprintf(w, "\n  [skipped] %s\n", s)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "%d workflow(s), %d job(s), %d finding(s)",
		r.Summary.Workflows, r.Summary.Jobs, r.Summary.Findings)
	if r.Summary.JobsEstablishNothing > 0 {
		fmt.Fprintf(w, " — %d job(s) establish nothing", r.Summary.JobsEstablishNothing)
	}
	if r.Summary.JobsUnanalysed > 0 {
		fmt.Fprintf(w, " — %d job(s) too opaque to read", r.Summary.JobsUnanalysed)
	}
	fmt.Fprintln(w)
}

func countOrNone(xs []string) string {
	if len(xs) == 0 {
		return "none"
	}
	if len(xs) <= 3 {
		return strings.Join(xs, ", ")
	}
	return fmt.Sprintf("%s (+%d)", strings.Join(xs[:3], ", "), len(xs)-3)
}
