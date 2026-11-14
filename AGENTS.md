# Agent Operational Guidelines for gatescan

<!-- helm-sdlc-baseline:v1 -->
Apply the [HELM SDLC baseline](https://github.com/Mindburn-Labs/docs/blob/main/ai/sdlc.md).
Before implementation, define the outcome and observable acceptance conditions.
Use the existing tracker and isolated worktree; verify in proportion to risk with
the owning repository's checks. Bind results to the tested source and configuration.
Missing, skipped or inconclusive required checks are not passes. Report source,
CI, release, deployment, runtime and user acceptance separately; verify applicable
rollback, restoration and external-effect recovery. Use `Refs` while acceptance
work remains and `Closes` only when the whole issue is fulfilled. Preserve existing
authority boundaries and never bypass failed checks or move published tags.
<!-- /helm-sdlc-baseline -->

gatescan is an offline Go CLI. It reads GitHub Actions workflows and, for every
check they contain, reports whether any external referent could make it fail,
as a terminal table plus `report.json` and `report.html`. It is an early
prototype (v0.1). It makes no network calls and never executes the workflows it
scans.

## Dev Commands
* Check: `make check` (what CI runs) builds, vets and tests, then fails on
  unformatted Go files.
* Build: `make build` (`go build ./...`)
* Test: `make test` (`go test ./...`)
* Format: `make fmt` (`gofmt -l -w .`)
* Demo: `make demo` scans `fixtures/` and writes `report.json` and
  `report.html` to the repository root (gitignored). It exits non-zero on
  purpose: the fixtures contain critical findings. `make clean` removes the
  reports.
* Honest fixture: `GOWORK=off go run ./cmd/gatescan scan -fail-on medium fixtures/honest-gate.yml`
  must exit 0. No Go test covers it, so run it after changing a rule.

The Makefile sets `GOWORK=off`, so the module builds standalone.

## Boundaries
From the README:
* Precision over recall: where the shell is ambiguous, report nothing rather
  than a finding the scan cannot prove.
* A rule that cannot run says so in the report; it never counts as a pass.
* Every file under `fixtures/` is synthetic. Never commit third-party workflow
  content; `subjects/` is gitignored for fetched subjects.
