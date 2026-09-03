package detect

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// An acceptance records a human decision that a finding is understood and
// tolerated. It is deliberately not an ignore list.
//
// A rule that keeps reporting something nobody will ever act on teaches people
// to scroll past the report, and the next real finding goes with it. The two
// ways out are to weaken the rule until it stops noticing, or to write down
// that someone looked and decided. Only the second survives being asked about
// later, so acceptances demand a reason and are reported rather than hidden.
type Acceptance struct {
	Rule string `json:"rule"`
	// Path matches the workflow file by suffix, so acceptances survive being
	// read from a different working directory.
	Path string `json:"path"`
	// Match is a substring of the finding's detail. Line numbers are not used:
	// they move, and an acceptance that silently slides onto a different
	// finding is worse than none.
	Match  string `json:"match"`
	Reason string `json:"reason"`
	By     string `json:"by,omitempty"`
	At     string `json:"at,omitempty"`
}

// AcceptFile is the on-disk form.
type AcceptFile struct {
	Acceptances []Acceptance `json:"acceptances"`
}

// LoadAcceptances reads an acceptance file. Every entry must name a rule, a
// match and a reason; an entry missing any of them is an error rather than a
// silent skip, because a malformed acceptance would otherwise read as an
// accepted finding.
func LoadAcceptances(path string) ([]Acceptance, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f AcceptFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for i, a := range f.Acceptances {
		switch {
		case strings.TrimSpace(a.Rule) == "":
			return nil, fmt.Errorf("%s: acceptance %d names no rule", path, i)
		case strings.TrimSpace(a.Match) == "":
			return nil, fmt.Errorf("%s: acceptance %d has no match string", path, i)
		case strings.TrimSpace(a.Reason) == "":
			return nil, fmt.Errorf("%s: acceptance %d has no reason; an acceptance without one is an ignore list", path, i)
		}
	}
	return f.Acceptances, nil
}

// matches reports whether this acceptance covers f.
func (a Acceptance) matches(f Finding, workflowPath string) bool {
	if a.Rule != f.Rule {
		return false
	}
	if a.Path != "" && !strings.HasSuffix(workflowPath, a.Path) {
		return false
	}
	return strings.Contains(f.Detail, a.Match)
}

// Accepted is a finding a human decided to tolerate, carried with the decision.
type Accepted struct {
	Finding Finding `json:"finding"`
	Reason  string  `json:"reason"`
	By      string  `json:"by,omitempty"`
	At      string  `json:"at,omitempty"`
}

// applyAcceptances splits findings into those still outstanding and those a
// human has accepted, and reports acceptances that matched nothing.
//
// A stale acceptance is itself worth surfacing: it means the thing someone
// signed off on is gone, and the sign-off is now covering nothing — or worse,
// waiting to cover something else.
func applyAcceptances(res *Result, accs []Acceptance) {
	if len(accs) == 0 {
		return
	}
	used := make([]bool, len(accs))
	keep := res.Findings[:0]
	for _, f := range res.Findings {
		matched := -1
		for i, a := range accs {
			if a.matches(f, res.Path) {
				matched = i
				used[i] = true
				break
			}
		}
		if matched < 0 {
			keep = append(keep, f)
			continue
		}
		a := accs[matched]
		res.Accepted = append(res.Accepted, Accepted{Finding: f, Reason: a.Reason, By: a.By, At: a.At})
	}
	res.Findings = keep

	for i, a := range accs {
		if used[i] {
			continue
		}
		if a.Path != "" && !strings.HasSuffix(res.Path, a.Path) {
			continue // scoped to another file; not this scan's business
		}
		res.StaleAcceptances = append(res.StaleAcceptances,
			fmt.Sprintf("%s: %q matches nothing here any more", a.Rule, a.Match))
	}

	// Per-job findings are the same objects; re-filter so the two views agree.
	for i := range res.Jobs {
		jkeep := res.Jobs[i].Findings[:0]
		for _, f := range res.Jobs[i].Findings {
			accepted := false
			for _, a := range accs {
				if a.matches(f, res.Path) {
					accepted = true
					break
				}
			}
			if !accepted {
				jkeep = append(jkeep, f)
			}
		}
		res.Jobs[i].Findings = jkeep
	}
}
