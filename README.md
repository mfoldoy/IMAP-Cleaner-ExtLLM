# IMAP Cleaner for Hermes

**IMAP Cleaner (Hermes skill)** analyzes and tidies an IMAP mailbox without touching it by default.
- **Read-only audit:** exports metadata and short excerpts via `EXAMINE` / `FETCH BODY.PEEK`; flags are never changed.
- **Rule engine:** classifies phishing, spam, marketing and newsletters, and protects important mail (known correspondents, replies, finance, government, account security).
- **LLM triage (optional):** a local Ollama or OpenAI-compatible loopback model, or *agent mode*, where the Hermes model you selected classifies uncertain messages. The LLM can never demote protected mail, launder detected phishing or trigger actions.
- **Approval-gated cleanup:** a plan, a dry run, and a move to a `Hermes-Review` folder only after you type the confirmation phrase yourself. No permanent deletion or unsubscribe.
- **Offline tests:** a mock IMAP server covers the read-only guarantees, classification, LLM paths and quarantine.

Run it with `hermes chat --skills imap-cleaner-extllm`.

The first deliverable is a **read-only** analysis. Export, rule engine and report run locally; in the optional agent mode (see below) the Hermes model you have selected decides where excerpts of uncertain messages are sent.

- IMAP: `imap1.stwcp.net`, port `993`, SSL/TLS, username = full email address (SMTP is not used). The default host is a ServeTheWorld server; use `--host` for other providers.
- Requirements: Windows, Python 3.10+, Hermes. Optional: Ollama for a local LLM.

## Use it in Hermes

1. **Install the skill.** Copy this folder to the Hermes skills directory (the folder name must match the `name:` in `SKILL.md`):
   ```powershell
   robocopy . "$env:LOCALAPPDATA\hermes\skills\email\imap-cleaner-extllm" /E /XD reports logs __pycache__ .git
   ```
2. **Choose the model** Hermes should use (see the privacy note below):
   ```powershell
   hermes model        # pick Ollama (local) or OpenRouter (remote)
   ```
3. **Start Hermes with the skill loaded:**
   ```powershell
   hermes chat --skills imap-cleaner-extllm
   ```
4. Ask it to audit your mailbox. Because the IMAP password prompt needs a real terminal, Hermes will tell you to run the commands below in your own PowerShell; it never asks for the password in chat.

> **Privacy:** the skill cannot enforce local processing. The model you pick with `hermes model` decides where mail excerpts go in agent mode: **Ollama (local) = stays on your machine; OpenRouter or any other hosted model = the excerpts are sent to that provider.** Use Ollama for real email.

## Running the audit (in your own PowerShell)
```powershell
.\run-audit.ps1 -TestConnection     # tests login and folder structure, exports nothing
.\run-audit.ps1                     # export -> classification -> report
.\run-audit.ps1 -Llm ollama         # additionally use a local LLM for uncertain messages
```
The password is typed into a hidden prompt and is never stored or logged. Open `reports\report.md` and `reports\candidates.csv` yourself.

## Contents
| File | Purpose |
|---|---|
| `SKILL.md` | Hermes skill definition and agent instructions |
| `run-audit.ps1` | One-command audit: export, classify, report |
| `scripts/oc_common.py` | IMAP core (`SafeImap`: only EXAMINE/SEARCH/FETCH BODY.PEEK), UTF-7, parsing, logging |
| `scripts/imap_audit.py` | Export of all folders (UID + UIDVALIDITY), `--test-connection` |
| `scripts/classify.py`, `rules.py` | Rule engine (phishing, spam, marketing, newsletters) + protection of important mail; agent mode (`--export-uncertain`, `--import-verdicts`) |
| `scripts/llm_local.py` | Local LLM (Ollama/OpenAI-compatible), loopback only |
| `scripts/report.py` | Report (Markdown) and CSV; the console shows aggregate numbers only |
| `scripts/quarantine.py` | Approved cleanup: plan, dry run, move to `Hermes-Review` |
| `tests/` | Offline test suite against a mock IMAP server |

The keyword lists in `rules.py` contain both Norwegian and English terms, because they match the content of real mail.

## Safety
No permanent deletion, no unsubscribe, no flag changes during analysis. Protected messages (known correspondents, answered/flagged, work, finance, government, account security) are never proposed for moving. All actions are logged in `logs/actions.jsonl` (without passwords or content). `reports/` and `logs/` contain private data and are in `.gitignore`.

## Cleanup (after you have read the report)
```powershell
py -3 scripts\quarantine.py plan --category marketing
py -3 scripts\quarantine.py apply --user "you@example.com"             # dry run against the live mailbox
py -3 scripts\quarantine.py apply --user "you@example.com" --execute   # requires you to type: MOVE <count>
```

## Local LLM
```powershell
winget install Ollama.Ollama
ollama pull qwen2.5:7b-instruct
```
Only uncertain messages are sent (to `127.0.0.1`). Other hosts are rejected in the code. The code contains no client for external APIs.

## Agent mode (the Hermes model classifies uncertain messages)
> **Privacy:** the skill cannot enforce local processing. The model you have selected in Hermes decides where the excerpts are sent: **Ollama locally = stays on the machine; OpenRouter or any other hosted model = the excerpts are sent to that provider.** Use Ollama for real email. The script prints this notice on export.

```powershell
py -3 scripts\classify.py --export-uncertain reports\agent-input.jsonl     # uncertain messages (short excerpt) -> file
# The Hermes agent reads only that file and writes reports\agent-verdicts.jsonl:
#   {"id": "...", "category": "...", "confidence": 0.0-1.0, "reason": "...", "phishing_suspected": false}
py -3 scripts\classify.py --import-verdicts reports\agent-verdicts.jsonl   # validates and merges
py -3 scripts\report.py --classified reports\classified.jsonl
```
Verdicts are validated the same way as for the local LLM; unknown ids and invalid verdicts are discarded, and they can never demote protected mail, launder phishing or trigger actions. The agent treats email text as untrusted data and never runs `quarantine.py apply --execute` itself (you must type `MOVE <count>`). The report is labelled "Classified by the Hermes model (location decided by the user's model choice)". Delete the two files when you are done.

## Tests
```powershell
py -3 -W ignore -m unittest discover -s tests
```
The rule weights are heuristic and have not been validated on your real email; review the report before cleaning up.
