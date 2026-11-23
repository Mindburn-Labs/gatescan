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

var errFindings = errors.New("findings at or above the configured threshold")

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	repoDir := fs.String("repo", "", "repository root for the unreachable-subject rule")
	outDir := fs.String("out", ".", "directory for report.json and report.html")
	acceptPath := fs.String("accept", "", "JSON file of accepted findings, each with a stated reason")
	failOn := fs.String("fail-on", "critical", "exit non-zero at this severity or above")
	asJSON := fs.Bool("json", false, "print the JSON report to stdout")
	quiet := fs.Bool("quiet", false, "write report files without printing")
	if err := fs.Parse(hoistFlags(fs, args)); err != nil {
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
	if opts.Acceptances, err = detect.LoadAcceptances(*acceptPath); err != nil {
		return err
	}
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

// gitIgnoredFunc uses `git check-ignore` to apply Git's pattern precedence.
// When Git is unavailable, it treats every path as outside the ignore rules.
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
