// Command gatescan reads CI workflow definitions and answers one question for
// every check they contain: what external referent could make this fail?
//
// It performs static analysis only. No network access, no service dependency,
// nothing executed from the workflows it reads.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/gatescan/internal/detect"
	"github.com/Mindburn-Labs/gatescan/internal/report"
	"github.com/Mindburn-Labs/gatescan/internal/workflow"
)

const usage = `gatescan ` + report.Version + ` — offline gate admissibility scanner

usage:
  gatescan scan <file-or-dir> [flags]
  gatescan version

For every check in a CI workflow, gatescan asks what external referent could
make it fail. A check whose inputs were all produced by the same job cannot
fail, however much validation ceremony surrounds it.

flags:
  -repo DIR      repository root, enabling the unreachable-subject rule
                 (uses git check-ignore; without it that rule is skipped
                 and says so in the report rather than passing silently)
  -out DIR       directory for report.json and report.html (default ".")
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

var errFindings = errors.New("findings at or above the configured threshold")

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
	case "help", "--help", "-h":
		fmt.Print(usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q (try: gatescan help)", args[0])
	}

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	repoDir := fs.String("repo", "", "repository root for the unreachable-subject rule")
	outDir := fs.String("out", ".", "directory for report.json and report.html")
	failOn := fs.String("fail-on", "critical", "exit non-zero at this severity or above")
	asJSON := fs.Bool("json", false, "print the JSON report to stdout")
	quiet := fs.Bool("quiet", false, "write report files without printing")
	if err := fs.Parse(hoistFlags(fs, args[1:])); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("scan takes exactly one file or directory (try: gatescan help)")
	}
	subject := fs.Arg(0)

	files, err := collect(subject)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no workflow files found under %s", subject)
	}

	opts := detect.Options{}
	if *repoDir != "" {
		root, err := filepath.Abs(*repoDir)
		if err != nil {
			return err
		}
		opts.GitIgnored = gitIgnoredFunc(root)
		opts.PathExists = func(p string) bool {
			_, err := os.Stat(filepath.Join(root, p))
			return err == nil
		}
	}

	results := make([]*detect.Result, 0, len(files))
	for _, f := range files {
		wf, err := workflow.ParseFile(f)
		if err != nil {
			return err
		}
		results = append(results, detect.Run(wf, opts))
	}

	rep := report.Build(subject, results, time.Now())

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	jsonPath, err := report.WriteJSON(rep, *outDir)
	if err != nil {
		return err
	}
	htmlPath, err := report.WriteHTML(rep, *outDir)
	if err != nil {
		return err
	}

	switch {
	case *asJSON:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return err
		}
	case !*quiet:
		report.Terminal(os.Stdout, rep)
		fmt.Printf("\nwrote %s\nwrote %s\n", jsonPath, htmlPath)
	}

	if exceeds(rep, *failOn) {
		return errFindings
	}
	return nil
}

// hoistFlags reorders so flags precede positional arguments. Go's flag package
// stops at the first non-flag token, which would make "scan DIR -out X" silently
// drop -out; people write it that way, so accept it.
func hoistFlags(fs *flag.FlagSet, args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if strings.Contains(name, "=") {
			continue
		}
		f := fs.Lookup(name)
		if f == nil {
			continue
		}
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			continue
		}
		if i+1 < len(args) {
			flags = append(flags, args[i+1])
			i++
		}
	}
	return append(flags, positional...)
}

var severityOrder = map[string]int{"critical": 0, "high": 1, "medium": 2}

func exceeds(r *report.Report, level string) bool {
	if level == "none" {
		return false
	}
	limit, ok := severityOrder[level]
	if !ok {
		limit = severityOrder["critical"]
	}
	for sev, n := range r.Summary.BySeverity {
		if n > 0 && severityOrder[sev] <= limit {
			return true
		}
	}
	return false
}

// collect resolves the subject to a sorted list of workflow files.
func collect(subject string) ([]string, error) {
	info, err := os.Stat(subject)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{subject}, nil
	}
	var out []string
	err = filepath.WalkDir(subject, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if ext := strings.ToLower(filepath.Ext(p)); ext == ".yml" || ext == ".yaml" {
			out = append(out, p)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

// gitIgnoredFunc defers gitignore semantics to git itself.
//
// ponytail: shelling out to `git check-ignore` beats reimplementing the
// pattern language, which has precedence rules that are easy to get subtly
// wrong. If git is unavailable the rule reports every path as not-ignored,
// which under-reports rather than accusing falsely.
func gitIgnoredFunc(root string) func(string) bool {
	if _, err := exec.LookPath("git"); err != nil {
		return func(string) bool { return false }
	}
	cache := map[string]bool{}
	return func(p string) bool {
		if v, ok := cache[p]; ok {
			return v
		}
		cmd := exec.Command("git", "-C", root, "check-ignore", "-q", "--no-index", p)
		v := cmd.Run() == nil
		cache[p] = v
		return v
	}
}
