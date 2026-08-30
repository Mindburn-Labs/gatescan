package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/gatescan/internal/detect"
)

func sampleReport() *Report {
	res := &detect.Result{
		Path: "wf.yml",
		Name: "demo",
		Jobs: []detect.JobResult{{
			ID:      "gate",
			Verdict: detect.VerdictNothing,
			Assertions: []detect.Assertion{
				{Step: "validate", Line: 12, Internal: []string{"out/a.json"}},
			},
		}},
		Findings: []detect.Finding{
			{Rule: detect.RuleSelfReferential, Severity: detect.SeverityCritical, Step: "validate", Line: 12,
				Detail: "validates out/a.json", Referent: "none"},
			{Rule: detect.RuleAbsencePass, Severity: detect.SeverityHigh, Step: "verify", Line: 20,
				Detail: "iterates out/*.json", Referent: "none when empty"},
		},
	}
	return Build("wf.yml", []*detect.Result{res}, time.Unix(0, 0))
}

func TestBuildCountsBySeverityAndRule(t *testing.T) {
	r := sampleReport()
	if r.Summary.Findings != 2 || r.Summary.Jobs != 1 || r.Summary.Workflows != 1 {
		t.Fatalf("summary = %+v", r.Summary)
	}
	if r.Summary.BySeverity[detect.SeverityCritical] != 1 || r.Summary.BySeverity[detect.SeverityHigh] != 1 {
		t.Errorf("by severity = %v", r.Summary.BySeverity)
	}
	if r.Summary.JobsEstablishNothing != 1 {
		t.Errorf("jobs establishing nothing = %d, want 1", r.Summary.JobsEstablishNothing)
	}
	if r.Clean() {
		t.Error("Clean() true with findings present")
	}
}

func TestWriteJSONRoundTrips(t *testing.T) {
	dir := t.TempDir()
	path, err := WriteJSON(sampleReport(), dir)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("report.json is not valid JSON: %v", err)
	}
	if back.Tool != "gatescan" || back.Summary.Findings != 2 {
		t.Errorf("round trip lost data: %+v", back.Summary)
	}
	if len(back.Workflows) != 1 || len(back.Workflows[0].Findings) != 2 {
		t.Errorf("findings did not survive: %+v", back.Workflows)
	}
}

var externalRef = regexp.MustCompile(`(?i)<(script|link|img|iframe)\b|https?://`)

// The HTML report has to open offline, in an auditor's browser, with no
// network. Any external reference breaks that promise.
func TestWriteHTMLIsSelfContained(t *testing.T) {
	dir := t.TempDir()
	path, err := WriteHTML(sampleReport(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "report.html" {
		t.Errorf("path = %s", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	if m := externalRef.FindString(body); m != "" {
		t.Errorf("report.html reaches outside itself: %q", m)
	}
	for _, want := range []string{"self_referential_evidence", "ESTABLISHES_NOTHING", "gatescan report"} {
		if !strings.Contains(body, want) {
			t.Errorf("report.html missing %q", want)
		}
	}
}

func TestTerminalNamesTheQuestion(t *testing.T) {
	var sb strings.Builder
	Terminal(&sb, sampleReport())
	out := sb.String()
	for _, want := range []string{"external referent", "ESTABLISHES_NOTHING", "self_referential_evidence", "1 job(s) establish nothing"} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal output missing %q\n---\n%s", want, out)
		}
	}
}
