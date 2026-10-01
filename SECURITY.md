# Security

Report suspected vulnerabilities privately to
[security@mindburn.org](mailto:security@mindburn.org). Do not publish
vulnerability details in a public issue, pull request, or discussion.

gatescan is an offline command-line tool that parses GitHub Actions workflows
and generates findings. It does not execute the workflows it scans. Reports
can cover workflow parsing and report generation.

In your private report, include:

- The affected release, tag, or commit and your operating environment.
- A minimal synthetic or redacted workflow, command, and configuration needed
  to reproduce the behavior.
- The expected and actual behavior, likely security impact, and any known
  mitigation.

Remove tokens, secrets, private repository metadata, and confidential workflow
content from reproductions. Do not commit third-party workflow content to this
repository.
