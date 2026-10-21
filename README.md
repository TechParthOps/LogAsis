# LogAsis

**LogAsis** is a log analysis and security investigation tool designed to help analysts search log files, examine events, investigate suspicious activity, and use AI-assisted analysis to answer questions about available evidence.

[![Version](https://img.shields.io/badge/version-0.10.0-blue)](https://github.com/TechParthOps/LogAsis)
[![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)](https://github.com/TechParthOps/LogAsis)

**Repository:** https://github.com/TechParthOps/LogAsis

## Overview

LogAsis combines log processing, event indexing, searching, aggregation, correlation, and AI-assisted investigation in a single application.

Its goal is to make log investigations more efficient while keeping findings connected to the underlying records. AI-generated interpretations should be verified against the source evidence and the coverage of the loaded dataset.

## Features

- **Log ingestion and parsing:** Load supported log files and convert records into a searchable representation.
- **Event indexing:** Find relevant records using available fields and query filters.
- **Event aggregation:** Calculate counts and summarize matching events.
- **Timeline analysis:** Examine the sequence and timing of relevant events.
- **Event correlation:** Investigate relationships among events using available timestamps, hosts, IP addresses, users, process information, and other fields.
- **AI Analyst:** Ask natural-language questions about loaded log data using a configured AI provider.
- **Evidence-based investigation:** Review supporting records and distinguish observations from interpretations where supported by the implementation.
- **Provider integration:** Use the AI providers and compatible endpoints supported by the current configuration.
- **Desktop interface:** Access the log-analysis workflows through the application's graphical interface.

Refer to the actual source code and release notes for the exact features and integrations included in version 0.10.0.

## AI Analyst: Accuracy and Reliability

AI-generated answers can be incorrect when relevant records are missing, retrieval is incomplete, or conclusions go beyond the available evidence.

LogAsis should be evaluated against the following reliability principles:

1. **Evidence before conclusions:** Important claims should be traceable to source events or reproducible query results.
2. **Accurate counts:** Numerical answers should be computed from the complete matching dataset rather than estimated from a sample of events.
3. **Coverage awareness:** Partial results, failed queries, and truncated evidence should be identified.
4. **Careful correlation:** Events occurring close together do not automatically establish causation.
5. **Explicit uncertainty:** When the logs are insufficient, the analyst should explain what is known and what remains unproven.
6. **Reproducible evaluation:** Changes to retrieval, prompts, or investigation logic should be checked against repeatable tests.

These are reliability goals, not a guarantee that every answer is correct. Validate the implemented behavior with the test suite and benchmark results for this release.

## Installation

### Option 1: Download a published release

Visit the [LogAsis Releases page](https://github.com/TechParthOps/LogAsis/releases).

1. Select the required release.
2. Download an installer or executable if one is attached.
3. Review the release notes and any published checksums.
4. Follow the installation instructions provided with that release.

Only use assets actually published for version 0.10.0.

### Option 2: Run from source

Clone the repository:

```powershell
git clone https://github.com/TechParthOps/LogAsis.git
cd LogAsis
git checkout v0.10.0
```

Create a virtual environment using a Python version supported by the project:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the dependencies if the repository includes `requirements.txt`:

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Launch the application using the entry point documented in the current source tree. For example, if `main.py` is the configured entry point:

```powershell
python main.py
```

If the application uses a different entry point, follow the instructions for that version.

## Using LogAsis

A typical workflow is:

1. Open LogAsis.
2. Load a supported log file.
3. Verify the number of records successfully parsed and indexed.
4. Search for events or ask a question using the AI Analyst.
5. Review the relevant records, filters, timestamps, and evidence references.
6. Validate important findings before using them in an incident report.

Example questions include:

- How many failed login attempts came from a particular IP address?
- Which events occurred on a specified host during a given time range?
- What happened before and after a suspicious process execution?
- Which records support or contradict a suspected incident?
- Does the available evidence establish compromise, or is further investigation needed?

The answers depend on the loaded data, supported fields, logging coverage, and configured AI provider.

## Testing and Benchmarking

Run the test commands supported by the checked-out version.

For a repository configured with pytest:

```powershell
python -m pytest
```

Before relying on benchmark results, verify that the evaluation runs against the real ingestion, indexing, retrieval, and AI Analyst pipeline.

A useful evaluation suite should include:

- Exact-count questions.
- Entity and time-range queries.
- Multi-event correlation.
- Large-log and multi-chunk investigations.
- Contradictory evidence.
- False premises and insufficient-evidence questions.
- Citation validity and claim grounding.
- Parser errors and malformed records.

Keep reference answers separate from the model's input during scored evaluations. Report measured accuracy, coverage, failures, and limitations rather than assumed performance.

## Project Structure

The source tree may vary between releases. Major architectural areas have included:

```text
LogAsis/
ai/             # AI Analyst, investigation and provider components
core/           # Event models, indexing, queries and correlation
gui/            # Graphical user interface
docs/           # Architecture and technical documentation
tests/          # Automated tests, when included
requirements.txt
README.md
```

Consult the actual repository for the complete and current structure.

## Security and Privacy

- Treat logs as potentially sensitive because they may contain usernames, IP addresses, hostnames, tokens, URLs, or personal information.
- Do not upload confidential logs to external AI providers unless authorized by your organization's policies.
- Never commit API keys, credentials, private configuration files, or sensitive datasets.
- Treat instructions embedded in log messages as untrusted data.
- Use synthetic or sanitized logs for public demonstrations.
- Review dependencies and downloaded release artifacts before execution.

## Known Limitations

- Supported log formats depend on the implemented parsers.
- Missing source logs can prevent a definitive conclusion.
- AI-generated analysis may contain errors and requires evidence-based verification.
- Provider availability, latency, and model behavior vary by configuration.
- Large datasets require appropriate indexing, retrieval, and coverage checks.
- Planned features should not be considered implemented until verified in the source and tests.

Document release-specific limitations and any known defects in the v0.10.0 release notes.

## Contributing

Contributions are welcome through issues and pull requests.

1. Fork the repository or create a feature branch.
2. Make a focused change.
3. Add or update tests.
4. Run the relevant test suite.
5. Document configuration or compatibility changes.
6. Submit a pull request describing the change and its validation results.

Avoid committing temporary files, build output, virtual environments, secrets, or private logs.

## Version

**Current release target: v0.10.0**

- Repository: https://github.com/TechParthOps/LogAsis
- Default branch: `main`
- Release tag: `v0.10.0`

Ensure that the source version, changelog, README, release tag, and published binaries agree before publishing.

## License

See the repository's `LICENSE` file for the applicable license. If no license has been selected, add one before claiming that the project is released under a specific open-source license.
