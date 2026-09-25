# Agent Operational Guidelines for gatescan

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
