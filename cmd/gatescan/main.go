// Command gatescan inspects GitHub Actions workflows and reports which inputs
// each check relies on. It reads local workflow files without executing them.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/Mindburn-Labs/gatescan/internal/report"
)

const usage = `gatescan ` + report.Version + ` — offline gate admissibility scanner

usage:
  gatescan scan <file-or-dir> [flags]
  gatescan version

gatescan reports where workflow checks get their inputs. Checks that rely on
outputs from the same job may establish internal consistency. Independent
inputs can support stronger claims.

flags:
  -repo DIR      repository root, enabling the unreachable-subject rule
                 (uses git check-ignore; without it that rule is skipped
                 and says so in the report rather than passing silently)
  -out DIR       directory for report.json and report.html (default ".")
  -accept FILE   JSON file of accepted findings. Each entry needs a rule, a
                 match substring and a reason; an entry without a reason is
                 rejected, because that is an ignore list. Accepted findings
                 stay in the report with the decision attached, and a sign-off
                 that no longer matches anything is reported as stale.
  -fail-on LEVEL exit non-zero when a finding at or above LEVEL is present:
                 critical (default), high, medium, or none
  -json          print the JSON report to stdout instead of the table
  -quiet         write the report files without printing
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, errFindings) {
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "gatescan: "+err.Error())
		os.Exit(2)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(usage)
		return nil
	}
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Println("gatescan " + report.Version)
		return nil
	case "scan":
		return runScan(args[1:])
	case "help", "--help", "-h":
		fmt.Print(usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q (try: gatescan help)", args[0])
	}
}
