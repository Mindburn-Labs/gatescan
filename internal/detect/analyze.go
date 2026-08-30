package detect

import (
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/Mindburn-Labs/gatescan/internal/workflow"
)

// stepFacts is what one step does to the filesystem, as far as static reading
// of its shell can tell. Extraction is deliberately conservative: a missed
// write costs a missed finding, a phantom write costs a false accusation, and
// only one of those is acceptable in a tool whose whole job is credibility.
type stepFacts struct {
	Step workflow.Step

	// Writes are files this step creates or overwrites.
	Writes []string
	// Dirs are directories this step creates. Kept apart from Writes: making
	// a directory says nothing about what ends up inside it, so a directory
	// must never inherit the provenance of the step that mkdir'd it.
	Dirs []string
	// Refs are every path this step mentions, written or read.
	Refs []string
	// Gate is true when the step has an explicit failure path, i.e. it can
	// turn the job red rather than merely producing something.
	Gate bool
	// GlobLoops are shell glob iterations found in the step.
	GlobLoops []globLoop
	// Derives is true when the step ran a compiler or test runner, so its
	// output is a function of repository source rather than of literals the
	// step wrote itself.
	Derives bool
	// Egress names the external services this step contacts. A step that
	// talks to a registry, an API, or a remote is answerable to something
	// outside the job even when every path it touches is local.
	Egress []string
}

type globLoop struct {
	Glob    string
	Guarded bool // an emptiness check precedes the loop
}

var (
	// Redirection to a file. Excludes fd duplication (2>&1, >&2) and /dev/*.
	reRedirect = regexp.MustCompile(`(?:^|[^0-9&<>\-])>>?\s*("[^"]+"|'[^']+'|[^\s;|&)<>]+)`)
	reTee      = regexp.MustCompile(`\btee\s+(?:-a\s+)?("[^"]+"|'[^']+'|[^\s;|&)<>]+)`)
	reCpMv     = regexp.MustCompile(`\b(?:cp|mv)\s+(?:-[a-zA-Z]+\s+)*("[^"]+"|'[^']+'|[^\s]+)\s+("[^"]+"|'[^']+'|[^\s;|&)]+)`)
	reMkdir    = regexp.MustCompile(`\bmkdir\s+(?:-p\s+)?(.+)`)
	reNodeArgv = regexp.MustCompile(`\bnode\s+(?:-\s|-e\s+(?:'[^']*'|"[^"]*"))([^\n<]*)`)
	reVarTok   = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)
	reBareTok  = regexp.MustCompile(`("[^"\n]*/[^"\n]*"|'[^'\n]*/[^'\n]*'|[A-Za-z0-9_./$${}-]*/[A-Za-z0-9_./$${}*-]+)`)
	reForGlob  = regexp.MustCompile(`(?:for\s+\w+\s+in\s+|=\()\s*("[^"]*\*[^"]*"|'[^']*\*[^']*'|[^\s;)]*\*[^\s;)]*)`)
	reURLInRun = regexp.MustCompile(`https?://[^\s"'` + "`" + `),]+`)
	reEmptyChk = regexp.MustCompile(`(?:-eq\s+0|-z\s+|\bif-no-files-found|\[\[\s*\$\{#|\blength\s*===?\s*0|\.length\s*===?\s*0)`)
	// Shell-local assignment at the start of a line: VAR=value.
	reLocalAssign = regexp.MustCompile(`(?m)^\s*([A-Z_][A-Z0-9_]*)=("[^"\n]*"|'[^'\n]*'|[^\s;&|]+)`)
)

// egressCommands reach a service outside the runner, so a step running one has
// an external referent that no amount of local file analysis will reveal.
var egressCommands = []string{
	"docker push", "docker pull", "helm push", "oras push", "skopeo", "crane ",
	"cosign ", "gh release", "gh api", "gh pr", "npm publish", "twine upload",
	"wrangler deploy", "aws ", "gcloud ", "az ", "curl ", "wget ",
	"git push", "git fetch", "git clone", "git ls-remote",
}

// toolchainCommands consume repository source. Deliberately narrow: a bare
// `bash script.sh` is not here, because the script may do nothing but echo
// literals, which is precisely the case this must not excuse.
var toolchainCommands = []string{
	"go test", "go build", "go vet", "go run", "npm test", "npm run", "npm ci",
	"pnpm ", "yarn ", "pytest", "cargo ", "mvn ", "gradle ", "tsc", "make ",
	"dotnet ", "bazel ", "buf ", "terraform ",
}

// failureMarkers are the ways a run block can decide to fail the job.
var failureMarkers = []string{"exit 1", "process.exit(1)", "::error::", "exit(1)", "throw new Error"}

func unquote(s string) string { return strings.Trim(strings.TrimSpace(s), `"'`) }

// looksLikePath filters extracted tokens down to plausible filesystem paths.
func looksLikePath(s string) bool {
	if s == "" || !strings.Contains(s, "/") {
		return false
	}
	if strings.HasPrefix(s, "/dev/") || strings.HasPrefix(s, "&") {
		return false
	}
	// A leading glob segment means the directory part failed to resolve; the
	// fragment that survives is not a location anything can be said about.
	if strings.HasPrefix(s, "/*") || strings.HasPrefix(s, "*") {
		return false
	}
	// Prose, not a path: workflow commands (::error::…) and human sentences
	// often quote a path inside them. Under-reporting here is the safe side.
	if strings.Contains(s, "::") || strings.Contains(s, " ") {
		return false
	}
	if strings.Contains(s, "://") {
		return false
	}
	// A bare scheme-less URL fragment such as "github.com/x" is not a path.
	if strings.HasPrefix(s, "http") {
		return false
	}
	return true
}

func addPath(dst *[]string, raw string, env map[string]string) {
	p := workflow.Expand(unquote(raw), env)
	if looksLikePath(p) {
		*dst = append(*dst, p)
	}
}

// analyzeStep extracts what one step does, with env already resolved.
func analyzeStep(s workflow.Step, env map[string]string) stepFacts {
	f := stepFacts{Step: s}
	// Expand once over the whole block, against workflow env plus the block's
	// own shell-local assignments. Real workflows alias long artifact paths to
	// a local before globbing them, and without those aliases the extracted
	// path is a meaningless fragment like "/*.json".
	run := workflow.ExpandRaw(s.Run, withLocals(s.Run, env))
	if run == "" {
		// A `uses:` step still names paths through `with:`.
		for _, v := range s.With {
			addPath(&f.Refs, v, env)
		}
		sortUnique(&f.Refs)
		return f
	}

	low := strings.ToLower(run)
	for _, m := range failureMarkers {
		if strings.Contains(low, strings.ToLower(m)) {
			f.Gate = true
			break
		}
	}

	for _, m := range reRedirect.FindAllStringSubmatch(run, -1) {
		addPath(&f.Writes, m[1], env)
	}
	for _, m := range reTee.FindAllStringSubmatch(run, -1) {
		addPath(&f.Writes, m[1], env)
	}
	for _, m := range reCpMv.FindAllStringSubmatch(run, -1) {
		addPath(&f.Writes, m[2], env)
	}
	for _, m := range reMkdir.FindAllStringSubmatch(run, -1) {
		for _, tok := range strings.Fields(m[1]) {
			if strings.HasPrefix(tok, "-") {
				continue
			}
			// mkdir -p creates every missing ancestor, so the whole chain is
			// this job's output, not pre-existing repository content.
			p := workflow.Expand(unquote(tok), env)
			for p != "" && p != "." && p != "/" && looksLikePath(p) {
				f.Dirs = append(f.Dirs, p)
				p = parentDir(p)
			}
		}
	}
	// An inline node script that writes files does so at paths handed to it on
	// argv, so the shell-level argument list is where those paths are visible.
	if strings.Contains(run, "writeFileSync") || strings.Contains(run, "mkdirSync") {
		for _, m := range reNodeArgv.FindAllStringSubmatch(run, -1) {
			for _, tok := range strings.Fields(m[1]) {
				addPath(&f.Writes, tok, env)
			}
		}
	}

	for _, m := range reBareTok.FindAllStringSubmatch(run, -1) {
		addPath(&f.Refs, m[1], env)
	}
	for _, v := range s.Env {
		addPath(&f.Refs, v, env)
	}

	f.GlobLoops = findGlobLoops(run, env)
	f.Egress = findEgress(run)
	for _, c := range toolchainCommands {
		if strings.Contains(low, c) {
			f.Derives = true
			break
		}
	}

	sortUnique(&f.Writes)
	sortUnique(&f.Dirs)
	sortUnique(&f.Refs)
	return f
}

// findGlobLoops locates shell iterations over a glob and records whether an
// emptiness check appears before them. An unguarded glob loop that only fails
// from inside its body passes when the glob matches nothing.
func findGlobLoops(run string, env map[string]string) []globLoop {
	var out []globLoop
	for _, m := range reForGlob.FindAllStringSubmatchIndex(run, -1) {
		glob := workflow.Expand(unquote(run[m[2]:m[3]]), env)
		if !strings.Contains(glob, "*") {
			continue
		}
		// "Guarded" means an emptiness test appears anywhere in the block —
		// deliberately generous, so a real guard is never called missing.
		out = append(out, globLoop{Glob: glob, Guarded: reEmptyChk.MatchString(run)})
	}
	return out
}

// withLocals returns env extended with the run block's own VAR=value lines.
// Workflow env wins: a local cannot redefine what the job already fixed.
func withLocals(run string, env map[string]string) map[string]string {
	locals := make(map[string]string, len(env)+4)
	for _, m := range reLocalAssign.FindAllStringSubmatch(run, -1) {
		locals[m[1]] = unquote(m[2])
	}
	for k, v := range env {
		locals[k] = v
	}
	// Resolve locals defined in terms of other variables.
	for k, v := range locals {
		locals[k] = workflow.ExpandRaw(v, locals)
	}
	return locals
}

// parentDir returns the containing directory, or "" at the top.
func parentDir(p string) string {
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return ""
	}
	return p[:i]
}

// findEgress lists the external services a run block contacts, by command and
// by any URL it names on a host that really resolves.
func findEgress(run string) []string {
	var out []string
	low := strings.ToLower(run)
	for _, c := range egressCommands {
		if strings.Contains(low, c) {
			out = append(out, "network:"+strings.TrimSpace(c))
		}
	}
	for _, lit := range reURLInRun.FindAllString(run, -1) {
		if _, _, bad := anchorProblem(lit); bad != "" {
			continue
		}
		if u, err := url.Parse(lit); err == nil && u.Hostname() != "" {
			out = append(out, "network:"+u.Hostname())
		}
	}
	sortUnique(&out)
	return out
}

func sortUnique(xs *[]string) {
	seen := map[string]bool{}
	out := (*xs)[:0]
	for _, x := range *xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	*xs = out
}

// origin records which earlier step put a path there, and how.
type origin struct {
	Step     string
	ViaMkdir bool
}

// producedBefore is every path materialised by steps earlier in the job.
// Files win over directories: if a step wrote the file, that is its provenance,
// regardless of who created the enclosing directory.
func producedBefore(facts []stepFacts, upto int) map[string]origin {
	out := map[string]origin{}
	for i := 0; i < upto; i++ {
		for _, d := range facts[i].Dirs {
			if _, seen := out[d]; !seen {
				out[d] = origin{Step: facts[i].Step.Label(), ViaMkdir: true}
			}
		}
	}
	for i := 0; i < upto; i++ {
		for _, w := range facts[i].Writes {
			if o, seen := out[w]; !seen || o.ViaMkdir {
				out[w] = origin{Step: facts[i].Step.Label()}
			}
		}
	}
	return out
}

// coveredBy reports how ref came to exist, matching against produced files and
// against produced directories that contain it. The longest matching prefix
// wins, so a file's own writer beats a distant ancestor's mkdir.
func coveredBy(produced map[string]origin, ref string) (origin, bool) {
	if o, ok := produced[ref]; ok {
		return o, true
	}
	best, bestLen, found := origin{}, -1, false
	for p, o := range produced {
		if p != "" && strings.HasPrefix(ref, p+"/") && len(p) > bestLen {
			best, bestLen, found = o, len(p), true
		}
	}
	return best, found
}
