#!/usr/bin/env python3
"""BugSkills — Convert bug bounty reports into AI skills."""

import argparse
import os
import re
import sys
import time
from collections import defaultdict
from pathlib import Path

try:
    import httpx
except ImportError:
    sys.exit("Missing httpx. Run:\n  uv sync")

try:
    from dotenv import load_dotenv
except ImportError:
    sys.exit("Missing python-dotenv. Run:\n  uv sync")

load_dotenv()

# ── Config ───────────────────────────────────────────────────────────────────

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "anthropic/claude-sonnet-4")
H1_API_KEY = os.getenv("H1_API_KEY", "")  # format: identifier:token


# ── Helpers ──────────────────────────────────────────────────────────────────


def log(msg):
    print(f"[*] {msg}")


def warn(msg):
    print(f"[!] {msg}", file=sys.stderr)


def die(msg):
    print(f"[✗] {msg}", file=sys.stderr)
    sys.exit(1)


# ── Masking ──────────────────────────────────────────────────────────────────

_TLD = (
    r"(?:com|net|org|io|dev|co|app|xyz|info|biz|gov|edu|me|us|uk|ca|de|fr"
    r"|au|in|jp|cn|ru|br|nl|se|no|fi|it|es|pt|cz|at|ch|be|ie|nz)"
)


def mask_text(text, program_names=None):
    """Mask URLs, emails, IPs, domains, and known program names."""
    if not text:
        return ""
    # URLs first (before domain replacement)
    text = re.sub(r"https?://[^\s<>\"')\]]+", "[REDACTED_URL]", text)
    # Emails (before domains)
    text = re.sub(r"[\w.+-]+@[\w.-]+\.\w{2,}", "[REDACTED_EMAIL]", text)
    # IPv4
    text = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "[REDACTED_IP]", text)
    # Domains
    text = re.sub(
        rf"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+{_TLD}\b",
        "[REDACTED_DOMAIN]",
        text,
        flags=re.IGNORECASE,
    )
    # Program names
    for name in program_names or []:
        if name and len(name) > 2:
            text = re.sub(re.escape(name), "[REDACTED_PROGRAM]", text, flags=re.IGNORECASE)
    return text


def mask_report(r):
    """Return a copy of the report dict with sensitive fields masked."""
    progs = [r["program"]] if r.get("program") else []
    return {
        **r,
        "title": mask_text(r.get("title", ""), progs),
        "description": mask_text(r.get("description", ""), progs),
        "impact": mask_text(r.get("impact", ""), progs),
        "program": "[REDACTED_PROGRAM]",
    }


# ── HackerOne ────────────────────────────────────────────────────────────────


def _h1_auth():
    """Parse H1_API_KEY='identifier:token' into a Basic Auth tuple."""
    if H1_API_KEY and ":" in H1_API_KEY:
        ident, token = H1_API_KEY.split(":", 1)
        return (ident, token)
    return None


def _h1_username():
    auth = _h1_auth()
    return auth[0] if auth else None


def h1_fetch_own():
    """Fetch your own resolved + triaged reports via HackerOne REST API v1."""
    auth = _h1_auth()
    if not auth:
        die("H1_API_KEY missing or invalid. Expected format: identifier:token")

    url = "https://api.hackerone.com/v1/hackers/me/reports"
    params = {"filter[state][]": ["triaged", "resolved"], "page[size]": "100"}
    reports = []

    with httpx.Client(timeout=30) as client:
        pg = 1
        while url:
            log(f"HackerOne — fetching page {pg}...")
            try:
                resp = client.get(url, params=params, auth=auth)
            except httpx.RequestError as e:
                warn(f"Network error: {e}")
                break

            if resp.status_code == 401:
                die("HackerOne auth failed — check H1_API_KEY")
            if resp.status_code == 403:
                die("HackerOne API access forbidden — check API key permissions")
            if resp.status_code != 200:
                die(f"HackerOne API {resp.status_code}: {resp.text[:300]}")

            data = resp.json()
            for item in data.get("data", []):
                a = item.get("attributes", {})
                rel = item.get("relationships", {})
                weakness = (
                    rel.get("weakness", {})
                    .get("data", {})
                    .get("attributes", {})
                    .get("name", "")
                )
                program = rel.get("program", {}).get("data", {}).get(
                    "attributes", {}
                ).get("handle", "") or rel.get("team", {}).get("data", {}).get(
                    "attributes", {}
                ).get(
                    "handle", ""
                )
                reports.append(
                    {
                        "title": a.get("title", "Untitled"),
                        "vulnerability_type": weakness or "unknown",
                        "severity": a.get("severity_rating") or "unknown",
                        "description": a.get("vulnerability_information", ""),
                        "impact": a.get("impact", ""),
                        "state": a.get("state", ""),
                        "program": program,
                        "source": "hackerone",
                    }
                )

            nxt = data.get("links", {}).get("next")
            url = nxt if nxt and nxt != url else None
            params = {}
            pg += 1

    return reports


# ── OpenRouter AI Analysis ───────────────────────────────────────────────────

_SKILL_PROMPT = """\
You are an expert bug bounty researcher. Analyze these {count} resolved/triaged \
bug reports (classified as "{vuln_type}") and extract reusable patterns.

{reports_text}

Generate a skill file in EXACTLY this format:

---
name: {{kebab-case-name}}
description: {{1-2 sentence description of what this skill covers and when to invoke it. Include trigger words/phrases an AI would match on.}}
---

# {{Bug Type}} Hunting

## Patterns
{{Common patterns, code/config indicators, and vulnerability signatures seen across these reports}}

## Methodology
{{Step-by-step approach to finding and confirming this vulnerability}}

## Key Signals
{{Recon signals and indicators that suggest this vulnerability might be present}}

## Bypass Techniques
{{Evasion and bypass techniques observed in the reports}}

## Example Scenarios
{{2-3 anonymized scenarios showing the vulnerability pattern without revealing real details}}

Rules:
- NO real URLs, domains, IPs, emails, or program names — keep everything anonymized
- Focus on transferable, reusable techniques — not report-specific details
- Be concrete and actionable — an AI coding assistant will use this skill to hunt similar bugs
- name must be lowercase kebab-case (e.g. "stored-xss", "idor-exploitation", "ssrf-via-pdf")
- description must mention when/how this skill should be triggered\
"""


def ai_analyze(grouped):
    """Send grouped masked reports to OpenRouter and get skill definitions back."""
    if not OPENROUTER_API_KEY:
        die("OPENROUTER_API_KEY not set in .env")

    skills = {}
    total = len(grouped)

    for i, (vtype, reports) in enumerate(grouped.items(), 1):
        try:
            log(f"Analyzing '{vtype}' ({i}/{total}, {len(reports)} report{'s' if len(reports) != 1 else ''})...")
        except KeyboardInterrupt:
            warn(f"Interrupted — returning {len(skills)} skill(s) generated so far")
            return skills

        # Build reports text block
        parts = []
        for j, r in enumerate(reports, 1):
            lines = [
                f"--- Report {j} ---",
                f"Title: {r['title']}",
                f"Severity: {r['severity']}",
            ]
            if r.get("description"):
                lines.append(f"Description:\n{r['description'][:3000]}")
            if r.get("impact"):
                lines.append(f"Impact:\n{r['impact'][:1000]}")
            parts.append("\n".join(lines))

        prompt = _SKILL_PROMPT.format(
            count=len(reports),
            vuln_type=vtype,
            reports_text="\n\n".join(parts),
        )

        # Retry up to 3 times on rate limits
        content = None
        for attempt in range(3):
            if attempt > 0 or i > 1:
                try:
                    time.sleep(1)  # polite delay between calls
                except KeyboardInterrupt:
                    warn(f"Interrupted — returning {len(skills)} skill(s) generated so far")
                    return skills

            try:
                resp = httpx.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": OPENROUTER_MODEL,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.3,
                        "max_tokens": 4096,
                    },
                    timeout=120.0,
                )
            except KeyboardInterrupt:
                warn(f"Interrupted during API call — returning {len(skills)} skill(s) generated so far")
                return skills
            except httpx.RequestError as e:
                warn(f"Network error for '{vtype}': {e}")
                break

            if resp.status_code == 401:
                die("OpenRouter auth failed — check OPENROUTER_API_KEY in .env")
            if resp.status_code == 429:
                wait = 10 * (attempt + 1)
                warn(f"Rate limited, waiting {wait}s before retry...")
                try:
                    time.sleep(wait)
                except KeyboardInterrupt:
                    warn(f"Interrupted — returning {len(skills)} skill(s) generated so far")
                    return skills
                continue
            if resp.status_code != 200:
                warn(f"OpenRouter {resp.status_code} for '{vtype}': {resp.text[:200]}")
                break

            data = resp.json()
            content = (
                data.get("choices", [{}])[0].get("message", {}).get("content", "")
            )
            break

        if content:
            skills[vtype] = content.strip()
        else:
            warn(f"No skill generated for '{vtype}'")

    return skills


# ── Skill File Writer ────────────────────────────────────────────────────────


def _ensure_frontmatter(content, vuln_type):
    """If the AI didn't produce proper frontmatter, add it."""
    if content.strip().startswith("---"):
        return content
    name = re.sub(r"[^a-z0-9]+", "-", vuln_type.lower()).strip("-")
    fm = f"---\nname: {name}\ndescription: Techniques for finding and exploiting {vuln_type} vulnerabilities.\n---\n\n"
    return fm + content


def write_skills(skills, output_dir):
    """Write each skill to a .md file and create an index README."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    written = []
    for vtype, content in skills.items():
        content = _ensure_frontmatter(content, vtype)

        # Derive filename from frontmatter name field
        m = re.search(r"^name:\s*(.+)$", content, re.MULTILINE)
        fname = m.group(1).strip() if m else re.sub(r"[^a-z0-9]+", "-", vtype.lower()).strip("-")
        if not fname.endswith(".md"):
            fname += ".md"

        path = out / fname
        path.write_text(content + "\n", encoding="utf-8")
        written.append(path)
        log(f"  → {path}")

    # Index
    if written:
        idx = out / "README.md"
        lines = ["# Generated Bug Bounty Skills\n\n"]
        for p in sorted(written):
            text = p.read_text(encoding="utf-8")
            dm = re.search(r"^description:\s*(.+)$", text, re.MULTILINE)
            desc = dm.group(1).strip() if dm else ""
            lines.append(f"- **[{p.stem}]({p.name})** — {desc}\n")
        idx.write_text("".join(lines), encoding="utf-8")
        log(f"  → {idx}")

    return written


# ── CLI ──────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="BugSkills — Convert bug bounty reports into AI skills",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=None,
        help="Output directory (default: <username>-skills)",
    )
    args = parser.parse_args()

    # ── Resolve username ──
    username = _h1_username() or "me"
    output_dir = args.output_dir or f"{username}-skills"

    log(f"User: {username}")
    log(f"Output: {output_dir}/")

    # ── Fetch reports ──
    reports = h1_fetch_own()

    if not reports:
        die(
            f"No reports found for '{username}' on HackerOne.\n"
            "    Possible causes:\n"
            "    • No resolved/triaged reports on this account\n"
            "    • H1_API_KEY is missing, invalid, or lacks permissions"
        )

    log(f"Fetched {len(reports)} reports")

    # ── Mask sensitive data ──
    log("Masking sensitive data...")
    masked = [mask_report(r) for r in reports]

    # ── Group by vulnerability type ──
    grouped = defaultdict(list)
    for r in masked:
        grouped[r.get("vulnerability_type") or "Miscellaneous"].append(r)

    log(f"{len(grouped)} vulnerability types found:")
    for vt, grp in sorted(grouped.items(), key=lambda x: -len(x[1])):
        log(f"  • {vt} ({len(grp)})")

    # ── AI analysis ──
    log(f"Sending to AI for analysis ({OPENROUTER_MODEL})...")
    try:
        skills = ai_analyze(grouped)
    except KeyboardInterrupt:
        skills = {}
        warn("Interrupted before any skills were generated")

    if not skills:
        die("No skills generated. Check OPENROUTER_API_KEY and OPENROUTER_MODEL in .env.")

    # ── Write skill files ──
    log("Writing skill files...")
    written = write_skills(skills, output_dir)

    log(f"Done! {len(written)} skill(s) written to {output_dir}/")


if __name__ == "__main__":
    main()
