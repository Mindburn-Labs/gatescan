# gatescan

Offline scanner for CI gates. Point it at the workflows you already have; for
every check they contain it asks one question:

> **What external referent could make this fail?**

A check whose every input was produced by the same job moments earlier is not a
check. It reports green for the same reason a mirror agrees with you, however
much validation ceremony surrounds it. gatescan finds the shapes that produce
that outcome, and cites the line.

Workflows in → admissibility report out. Nothing else: no network calls, no
service dependency, nothing from the scanned workflows is executed.

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

Per job, from its checks — a check being any step that can turn the run red:

| Verdict | Meaning |
| --- | --- |
| `ESTABLISHES` | every check has at least one input it did not produce |
| `PARTIAL` | some checks rest entirely on inputs this job produced |
| `ESTABLISHES_NOTHING` | every check rests entirely on inputs this job produced |
| `NO_ASSERTIONS` | no step in this job can fail the run |

## Rules

| Rule | Severity | What it finds |
| --- | --- | --- |
| `self_referential_evidence` | critical | A check validating only paths an earlier step in the same job wrote. |
| `fabricated_fallback` | critical | A branch that runs *because* the subject is missing, and writes the evidence a later check reads. |
| `unreachable_subject` | critical | A path filter naming something the repository excludes, so no commit can ever trigger the gate. |
| `synthetic_anchor` | high | An evidence reference pointing at a reserved host (RFC 2606 / RFC 6761) or a scheme that names no retrievable location. |
| `suppressed_evidence_step` | high | `continue-on-error: true` on a step producing artifacts a later check consumes. |
| `absence_reads_as_pass` | high | A glob iteration that fails only from inside its body, so zero matches exits zero. |

Rules that cannot be evaluated say so. `unreachable_subject` needs `-repo` to
consult the repository's own ignore rules; without it the report records that
the rule did not run, rather than contributing a silent pass. A scanner that
quietly skips is the defect it exists to find.

## Precision over recall

Extraction is deliberately conservative. A missed write costs a missed finding;
a phantom write costs a false accusation, and only one of those is survivable
in a tool whose entire value is being believed. Where the shell is ambiguous,
gatescan stays quiet.

`fixtures/honest-gate.yml` exists to hold that line: a workflow whose checks
read committed repository content and refuse to pass on an empty set. It must
scan clean. A scanner that flags everything is worth nothing.

## Limits

- GitHub Actions workflow syntax only.
- Static shell reading. Paths assembled at runtime by a program gatescan cannot
  read are invisible to it; a clean report is not proof of a sound gate.
- `unreachable_subject` shells out to `git check-ignore` rather than
  reimplementing the pattern language. Without git, it reports nothing.
- Reachability is judged per job. Evidence handed between jobs through uploaded
  artifacts is not yet followed.

## Clean room

gatescan ships no third-party workflow content. Every file under `fixtures/` is
synthetic, written for these tests, and reproduces a *pattern* rather than any
particular repository's code. Scan someone else's workflow by pointing the tool
at it; nothing needs to be copied in.

## License

Apache-2.0. See [LICENSE](LICENSE).
