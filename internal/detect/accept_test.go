package detect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeAccept(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "accept.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const anchorWorkflow = `
name: t
on: [push]
jobs:
  g:
    steps:
      - name: record
        run: |
          mkdir -p out
          echo '{"sig":"cosign://ghcr.io/org/app:v1"}' > out/a.json
`

// An accepted finding stays in the report carrying the decision, rather than
// disappearing. Someone reading the report later must be able to see that a
// person looked at this and why they were content.
func TestAcceptanceKeepsTheFindingVisibleWithItsReason(t *testing.T) {
	accs, err := LoadAcceptances(writeAccept(t, `{"acceptances":[
      {"rule":"unresolvable_anchor","match":"cosign","reason":"the image digest in the same record pins what this names","by":"ivan","at":"2026-09-03"}
    ]}`))
	if err != nil {
		t.Fatal(err)
	}
	res := scan(t, anchorWorkflow, Options{Acceptances: accs})

	if n := rules(res)[RuleUnresolvable]; n != 0 {
		t.Errorf("accepted finding still outstanding: %+v", res.Findings)
	}
	if len(res.Accepted) != 1 {
		t.Fatalf("accepted = %d, want 1", len(res.Accepted))
	}
	if res.Accepted[0].Reason == "" || res.Accepted[0].By != "ivan" {
		t.Errorf("decision not carried: %+v", res.Accepted[0])
	}
	for _, j := range res.Jobs {
		for _, f := range j.Findings {
			if f.Rule == RuleUnresolvable {
				t.Error("per-job view disagrees with the top-level view")
			}
		}
	}
}

// Without a reason it is an ignore list, and that is the thing this exists to
// avoid becoming. Reject it loudly rather than skipping the entry, which would
// read as an accepted finding.
func TestAcceptanceWithoutAReasonIsRejected(t *testing.T) {
	for _, body := range []string{
		`{"acceptances":[{"rule":"unresolvable_anchor","match":"cosign"}]}`,
		`{"acceptances":[{"rule":"unresolvable_anchor","match":"cosign","reason":"   "}]}`,
		`{"acceptances":[{"match":"cosign","reason":"because"}]}`,
		`{"acceptances":[{"rule":"unresolvable_anchor","reason":"because"}]}`,
	} {
		if _, err := LoadAcceptances(writeAccept(t, body)); err == nil {
			t.Errorf("accepted a malformed entry: %s", body)
		}
	}
}

// A sign-off covering nothing is worth surfacing: either the thing is gone, or
// the sign-off is sitting there waiting to cover something else.
func TestStaleAcceptanceIsReported(t *testing.T) {
	accs, err := LoadAcceptances(writeAccept(t, `{"acceptances":[
      {"rule":"unresolvable_anchor","match":"this-scheme-is-long-gone","reason":"kept past its usefulness"}
    ]}`))
	if err != nil {
		t.Fatal(err)
	}
	res := scan(t, anchorWorkflow, Options{Acceptances: accs})
	if len(res.StaleAcceptances) != 1 {
		t.Fatalf("stale = %d, want 1: %+v", len(res.StaleAcceptances), res.StaleAcceptances)
	}
	if !strings.Contains(res.StaleAcceptances[0], "this-scheme-is-long-gone") {
		t.Errorf("stale note does not name the acceptance: %s", res.StaleAcceptances[0])
	}
}

// An acceptance scoped to one file must not silence the same shape elsewhere.
func TestAcceptanceScopedByPathDoesNotLeak(t *testing.T) {
	accs, err := LoadAcceptances(writeAccept(t, `{"acceptances":[
      {"rule":"unresolvable_anchor","path":"other.yml","match":"cosign","reason":"reviewed there, not here"}
    ]}`))
	if err != nil {
		t.Fatal(err)
	}
	res := scan(t, anchorWorkflow, Options{Acceptances: accs})
	if n := rules(res)[RuleUnresolvable]; n != 1 {
		t.Errorf("an acceptance for another file silenced this one: %+v", res.Findings)
	}
	if len(res.StaleAcceptances) != 0 {
		t.Errorf("an acceptance scoped elsewhere was called stale here: %v", res.StaleAcceptances)
	}
}

func TestNoAcceptanceFileIsNotAnError(t *testing.T) {
	accs, err := LoadAcceptances("")
	if err != nil || accs != nil {
		t.Errorf("LoadAcceptances(\"\") = %v, %v", accs, err)
	}
}
