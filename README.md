# gatescan

gatescan reads GitHub Actions workflows and reports which inputs it can identify
for each check. It flags patterns that weaken a gate, such as a check that
validates only files written earlier in the same job. Findings cite the
workflow line.

Scanning runs offline and reads workflows as text.

**Status: early prototype (v0.1).** The rule set and report formats may still
change. Built by [Mindburn Labs](https://mindburn.org).

## Quickstart

With Go 1.25+:

```sh
# scan a workflow, or a directory of them
go run github.com/Mindburn-Labs/gatescan/cmd/gatescan@latest scan .github/workflows

# or install the binary
go install github.com/Mindburn-Labs/gatescan/cmd/gatescan@latest
```

Or clone and run the bundled fixtures:

```sh
git clone https://github.com/Mindburn-Labs/gatescan
cd gatescan
make demo   # = go run ./cmd/gatescan scan fixtures
```

Every scan prints a table and writes `report.json` (machine-readable, every
finding with its rule, severity, line, and referent) and `report.html` (single
self-contained file, no scripts, opens offline) to the current directory.

```
-repo DIR       repository root, enabling the unreachable-subject rule
-out DIR        where the reports are written (default ".")
-fail-on LEVEL  exit non-zero at critical (default), high, medium, or none
-json           print the JSON report to stdout
-quiet          write the report files without printing
```

`-fail-on` makes gatescan usable as a gate over your gates. It exits 2 on its
own errors, 1 on findings at or above the threshold, 0 otherwise.

## What a scan looks like

Example output for a job that validates evidence from one of its own steps:

```
gatescan 0.1.0-prototype — offline gate admissibility scan
subject: .github/workflows/finance-gate.yml
question: For each check in these workflows: what external referent could make it fail?

finance-gate  (.github/workflows/finance-gate.yml)
  job export-evidence-gate         ESTABLISHES_NOTHING  every check rests entirely on inputs this job produced
      check "Validate export result contract"
          external inputs: none
          internal inputs: services/invoice-export/.ci/evidence/result/export-result.json

  [CRITICAL] self_referential_evidence
      step: Validate export result contract
      at:   .github/workflows/finance-gate.yml:46
      what: validates services/invoice-export/.ci/evidence/result/export-result.json,
            every one of which was written earlier in this same job ("Synthesise export evidence")
      referent: none — this check compares the job's output against the job's output, so it cannot fail
```

## Verdicts

Per job, from its evidence assertions. These are explicit failure blocks,
path-verification tools, and conventional source test commands:

| Verdict | Meaning |
| --- | --- |
| `ESTABLISHES` | every check has at least one input it did not produce |
| `PARTIAL` | some checks rest entirely on inputs this job produced |
| `ESTABLISHES_NOTHING` | every check rests entirely on inputs this job produced |
| `NO_ASSERTIONS` | no evidence assertion was identified in this job |
| `INPUTS_NOT_IDENTIFIED` | the checks' shell was too opaque to read — **not** a verdict on the gate |

Opaque checks receive `INPUTS_NOT_IDENTIFIED`. An early version
misclassified its own `gofmt` step because its inputs were opaque to the scanner.

## Rules

| Rule | Severity | What it finds |
| --- | --- | --- |
| `self_referential_evidence` | critical | A check validating only paths an earlier step in the same job wrote. |
| `fabricated_fallback` | critical | A branch that runs *because* the subject is missing, and writes the evidence a later check reads. |
| `unreachable_subject` | critical | A path filter naming something the repository excludes, so no commit can ever trigger the gate. |
| `synthetic_anchor` | high | An evidence reference on a reserved documentation host (RFC 2606). Fake by standard; no local convention rescues it. |
| `unresolvable_anchor` | medium | An evidence reference using a non-standard URI scheme. May be a sound in-house locator — the workflow cannot say, so this is raised for a human and left below the default failure threshold. |
| `suppressed_evidence_step` | high | `continue-on-error: true` on a step producing artifacts a later check consumes. |
| `absence_reads_as_pass` | high | A glob iteration that fails only from inside its body, so zero matches exits zero. |

A digest for the same subject, such as `sbom_digest` alongside `sbom_ref` in
the same block, lets a reader verify the bytes after the locator expires. That
binding suppresses `unresolvable_anchor`. `synthetic_anchor` still reports
reserved documentation hosts.

`unreachable_subject` uses `-repo` to consult the repository's ignore rules.
Scanning without `-repo` records the rule as skipped.

## Accepted findings

An acceptance file records the reason for accepting a finding. For example,
a nonstandard URI may be a valid internal locator.

```sh
gatescan scan .github/workflows -accept accept.json
```

Each entry requires a `rule`, a `match` substring of the finding's detail,
and a `reason`. It can also specify a path suffix. An incomplete entry fails
validation. See [accept.example.json](accept.example.json).

Accepted findings remain in the report with the reason attached and are
excluded from the `-fail-on` threshold. Acceptance entries that no longer
match are reported as **stale**.

## Precision over recall

gatescan reports findings when it can identify the relevant inputs in the
workflow. The `fixtures/honest-gate.yml` fixture checks committed repository
content and fails on an empty input set. It should scan without findings.

## Limits

- GitHub Actions workflow syntax only.
- Static shell reading. Paths assembled at runtime by a program gatescan cannot
  read are invisible to it; a clean report is not proof of a sound gate. Jobs it
  could not read are counted separately and reported as `INPUTS_NOT_IDENTIFIED`,
  so coverage gaps show up as gaps.
- Assertions are classified as `explicit_failure`, `evidence_verification`
  (`diff`, `cmp`, `sha256sum -c`, `cosign verify`, `jq -e`, `test -s`,
  `buf breaking`, `go-apidiff`), or `source_test` (`make test`, `make check`,
  `go test`, package-manager test commands, and common language test runners).
  Arbitrary `run:` steps are not assertions merely because shell errors can
  fail the job.
- `unreachable_subject` shells out to `git check-ignore` rather than
  reimplementing the pattern language. Without git, it reports nothing.
- Reachability is judged per job. Evidence handed between jobs through uploaded
  artifacts is not yet followed.
- An artifact a compiler or test runner produced from repository source counts
  as having an external referent, since the referent is that source one hop
  beyond what shell reading can follow. A step that merely creates the
  directory confers nothing — only writing the file does.
- A step contacting a registry, remote, or API has an external referent by
  virtue of the service, so publish steps are not reported as vacuous checks.

## Clean room

gatescan ships no third-party workflow content. Every file under `fixtures/` is
synthetic, written for these tests, and reproduces a *pattern* rather than any
particular repository's code. Scan someone else's workflow by pointing the tool
at it; nothing needs to be copied in.

## License

Apache-2.0. See [LICENSE](LICENSE).
