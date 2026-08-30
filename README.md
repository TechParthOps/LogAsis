# LogAsis

LogAsis is a Windows desktop security-investigation workspace for analyzing security logs, correlating events, reviewing evidence, and using live AI for evidence-grounded investigation.

## Current release

**v0.9.5 — AI grounding repair + provider model guard**

## Features

- Security-log parsing and normalized event analysis
- JSON security-log support, including vendor-specific/custom fields
- Syslog-style text-log support
- Dynamic event filtering with selectable field values — no manual value entry required
- Cross-event correlation and timeline analysis
- Source/destination IP and authentication analysis
- Findings, evidence, and case workflows
- AI-directed investigation over the currently loaded log
- Dynamic retrieval across populated log fields
- Evidence IDs and claim-level grounding
- Human-readable AI answers rather than raw provider JSON
- Deterministic evidence and provenance validation around AI-generated interpretations
- Live AI provider support through the application's configuration UI
- NVIDIA NIM support with analyst-model validation
- Session-local AI result caching; no persistent AI answer cache
- No local LLM or Ollama dependency

## Architecture

```text
Uploaded security log
        |
        v
Parser / normalized event records
        |
        +----> Dashboard / Events / Timeline / IP / Authentication
        |
        v
Evidence identity + read-only investigation tools
        |
        +----> Search
        +----> Entity context
        +----> Timeline
        +----> Correlation
        +----> Overview
        |
        v
Live AI provider
        |
        v
Claim-level grounding / citation validation
        |
        v
Human-readable analyst report
```

LogAsis preserves populated source fields, including vendor-specific JSON fields, so those fields can be searched without adding a new hard-coded forensic rule.

The AI is **not** treated as the source of truth. Concrete claims are checked against evidence references before they are presented as analyst findings. When the evidence supports only an observation or inference, LogAsis keeps the wording qualified instead of turning an inference into a fact.

## Supported input

The current release includes parsers for:

- **JSON security logs**, including structured/vendor-specific fields
- **Syslog-style text logs**

The JSON parser supports structured records, newline-delimited JSON (NDJSON), wrapped JSON exports, and other supported JSON layouts handled by the parser layer.

Additional formats can be added through the parser layer.

## AI configuration

AI configuration is performed through the LogAsis UI.

The current provider layer supports:

- OpenAI
- Google Gemini
- NVIDIA NIM
- Configurable OpenAI-compatible endpoints

Provider model catalogs can be discovered from the configured provider where supported.

API credentials are handled locally by the application and **must not be committed to Git**.

> LogAsis requires an appropriately configured live AI provider for AI Analyst functionality. Core log parsing, event views, filtering, and deterministic analysis do not depend on a local LLM.

## Installation from source

### Requirements

- Windows
- Python 3.11 recommended
- A configured live AI provider for AI Analyst features

### Create a virtual environment

```powershell
py -3.11 -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

Upgrade pip:

```powershell
python -m pip install --upgrade pip
```

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

Start LogAsis:

```powershell
python LogAsis.py
```

The repository intentionally does **not** include the project's virtual environment or internal regression-test suite.

## First use

1. Start LogAsis with `python LogAsis.py`.
2. Load a supported security log using the application.
3. Review the detected log profile and normalized events.
4. Use the Events tab to inspect and filter records.
5. Select a filter field and choose one of the values discovered from the loaded log; manual value entry is not required for normal field/value filtering.
6. Configure a live AI provider from the AI configuration interface if AI investigation is required.
7. Ask questions about the currently loaded log in the AI Analyst.
8. Review the answer together with its evidence references and qualification/grounding information.

The Events filter does not silently restrict the AI investigation: AI analysis operates on the full loaded log rather than only the currently filtered Events view.

## Project structure

```text
LogAsis/
├── ai/                     # AI providers, investigation runtime, retrieval, grounding
├── core/                   # Evidence, cases, correlation, analysis, investigation state
├── gui/                    # PySide6 desktop interface
├── parsers/                # Log-format parsers
├── config/                 # Safe configuration templates
├── assets/                 # Application assets
├── data/                   # Local generated/user data; not committed
├── exports/                # Generated exports; not committed
├── runtime/                # Local runtime logs; not committed
├── docs/                   # Current architecture/provider/filter documentation
├── LogAsis.py              # Application entry point
├── requirements.txt        # Python dependencies
├── README.md
├── CHANGELOG.md
├── VERSION
└── VERSION.txt
```

## Security and privacy

LogAsis is intended for security-log investigation, and logs may contain sensitive information such as usernames, IP addresses, hostnames, commands, paths, or other forensic data.

Do not commit:

- Real investigation logs
- Personal or organizational log data
- API keys or provider credentials
- `.env` files
- Generated case/evidence data
- Runtime logs
- Exported investigation artifacts

The repository is configured to ignore common local secrets, runtime state, generated data, logs, caches, virtual environments, and forensic artifacts.

No real investigation dataset is included in this release. Development/test sample logs have been intentionally excluded from the public repository.

## AI grounding and limitations

LogAsis uses AI for investigation and interpretation, but provider output is not automatically considered forensic fact.

The grounding layer checks claims against evidence references and preserves distinctions such as:

- observed event vs. inferred activity
- successful authentication vs. proven account compromise
- file download/execution vs. proven attacker access
- observed artifact vs. proven malware classification

This is intended to reduce unsupported conclusions, but LogAsis should still be used as an investigation aid and not as a replacement for analyst judgment.

## Documentation

Current project documentation is available in `docs/`:

- `docs/ARCHITECTURE.md` — investigation pipeline and evidence boundary
- `docs/AI-PROVIDER-COMPATIBILITY.md` — live AI provider behavior and grounding
- `docs/DYNAMIC_EVENT_FILTERS.md` — event filtering behavior

See `CHANGELOG.md` for release history.

## Development

The public repository intentionally excludes the internal regression-test suite and development fixtures.

For local development, create your own virtual environment and install dependencies from `requirements.txt`.

## License

LogAsis is released under the **MIT License**. See [`LICENSE`](LICENSE) for the full license text.

---

**LogAsis v0.9.5**
