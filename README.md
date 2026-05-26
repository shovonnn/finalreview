# finalreview

`finalreview` is a CI-first Python package for agentic vulnerability review of source repositories. It scans the full codebase by default, ranks risky areas with deterministic heuristics, uses an LLM for deeper reasoning when configured, and exits non-zero only when a finding crosses the configured pipeline gate.

## Installation

```bash
pip install finalreview
```

Provider-specific extras:

```bash
pip install "finalreview[openai]"
pip install "finalreview[anthropic]"
pip install "finalreview[google]"
pip install "finalreview[all]"
```

## Quick Start

Deterministic-only review:

```bash
finalreview scan . --provider none
```

OpenAI-compatible review:

```bash
export OPENAI_API_KEY="..."
finalreview scan . \
  --provider openai-compatible \
  --base-url http://localhost:8000/v1 \
  --model gpt-4.1-mini \
  --fail-on high \
  --json-output finalreview-artifacts/report.json \
  --sarif-output finalreview-artifacts/report.sarif
```

Hosted providers can send whole files when the agent needs broader context. Use `--provider none` or a self-hosted OpenAI-compatible endpoint if you need to keep all analysis local.

## Configuration

`finalreview` loads configuration in this order:

1. CLI flags
2. Environment variables prefixed with `FINALREVIEW_`
3. An explicit `--config` TOML or JSON file
4. `[tool.finalreview]` in `pyproject.toml`

Example `pyproject.toml`:

```toml
[tool.finalreview]
provider = "none"
fail-on = "high"
min-confidence = "medium"
scope = "full"
artifacts-dir = "finalreview-artifacts"
max-llm-calls = 12
offline-enricher = "auto"
```

## CLI

```text
finalreview scan [PATH]
finalreview providers list
finalreview doctor
```

Key scan options:

- `--provider`, `--model`, `--base-url`, `--api-key-env`, `--config`
- `--fail-on {critical,high,medium,low,never}`, `--min-confidence {high,medium,low}`
- `--scope {full,diff}`, `--changed-from`, `--changed-to`
- `--json-output`, `--sarif-output`, `--markdown-output`, `--artifacts-dir`
- `--max-llm-calls`, `--concurrency`, `--timeout-seconds`, `--offline-enricher {auto,on,off}`


