# BugSkills

Convert your HackerOne resolved & triaged bug reports into reusable AI skill files.

BugSkills fetches your reports via the HackerOne API, masks all sensitive data (URLs, IPs, emails, domains, program names), sends the anonymized reports to an AI model via OpenRouter for pattern extraction, and outputs structured Markdown skill files, one per vulnerability type.

## How It Works

```
Fetch reports → Mask sensitive data → AI analysis → Skill files (.md)
```

1. **Fetch** — Pulls your resolved + triaged reports from HackerOne REST API v1
2. **Mask** — Strips URLs, IPs, emails, domains, and program names using regex
3. **Analyze** — Groups reports by vulnerability type and sends them to OpenRouter
4. **Generate** — Writes one `.md` skill file per bug type with patterns, methodology, key signals, and bypass techniques

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/getting-started/installation/) (package manager)
- [HackerOne API token](https://hackerone.com/settings/api_token/edit)
- [OpenRouter API key](https://openrouter.ai/keys)

## Setup

```bash
git clone https://github.com/BehiSecc/bugSkills.git
cd bugSkills

# Install dependencies
uv sync

# Configure API keys
cp .env.example .env
# Edit .env with your keys
```


## Usage

```bash
# Generate skills (output to <username>-skills/)
uv run bugskills.py

# Custom output directory
uv run bugskills.py -o ./my-skills
```

If you interrupt with `Ctrl+C` during AI analysis, any skills generated so far will still be saved.

## Output

Each skill file follows this format:

```markdown
---
name: stored-xss
description: Techniques for finding and exploiting Stored XSS vulnerabilities. Use when testing user input fields, rich text editors, or file uploads for script injection.
---

# Stored XSS Hunting

## Patterns
...

## Methodology
...

## Key Signals
...

## Bypass Techniques
...

## Example Scenarios
...
```

A `README.md` index is also generated in the output directory listing all skills.

## Privacy

- All sensitive data is masked **before** sending to the AI model
- URLs → `[REDACTED_URL]`
- IPs → `[REDACTED_IP]`
- Emails → `[REDACTED_EMAIL]`
- Domains → `[REDACTED_DOMAIN]`
- Program names → `[REDACTED_PROGRAM]`

