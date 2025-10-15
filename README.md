# Password Enforcer (CLI + Web)

Local, privacy-first password policy checker with optional dictionary/wordlist checks.  
Includes a slick web UI and a CI-friendly CLI. Hashes are stored locally.

## ✨ Features

- Score table + strength meter (6-point model)
- Policy checks: length, upper/lower, digit, symbol
- Dictionary/wordlist checks (`rockyou` etc.) with line-limit control
- CLI workflow (interactive + single-shot)
- Web UI workflow (upload or path for wordlist, show/hide password)
- Read-only view of the last saved hashes (CLI) or first N lines (Web)
- Stores bcrypt hashes in a local file with restrictive perms

---

## 🗂️ Project Layout

```
password_lab/
├─ password_enforcer_cli.py     # CLI entry point (recommended)
├─ password_enforcer_web.py     # Web UI entry point (Flask)
├─ password_enforcer.py         # (older CLI; optional to keep)
├─ pw_core.py                   # Shared core: policy, wordlist, hashing
├─ wordlists/                   # Your local lists (e.g., jack_the_reaper.txt)
├─ SecLists/                    # (optional) local clone of SecLists
```
---

## 🧰 Prerequisites

- Python 3.9+
- Recommended: create a venv

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install flask werkzeug bcrypt colorama
```

> If you use very large wordlists, ensure enough RAM and consider the `--max-lines` limit.

---

## 🚀 Quick Start

### CLI

```bash
# interactive check with a wordlist
python password_enforcer_cli.py   --wordlist ./wordlists/jack_the_reaper.txt   --max-lines 200000

# show last 3 saved hashes and exit
python password_enforcer_cli.py --show-hashes
```

The CLI prints the score table, validates your password, shows a score `/6`,  
and appends `username:bcrypt_hash` to `./password_hashes.txt` on success.

### Web UI

```bash
python password_enforcer_web.py   --wordlist ./wordlists/jack_the_reaper.txt   --max-lines 200000
# then open http://127.0.0.1:5000/  (auto-opens by default)
```

In the UI you can:
- upload a `.txt` wordlist or provide a path
- toggle “exact only” matches
- view a **read-only preview** of the hash file (first N lines)
- see a live strength meter and the server decision

---

## ⚙️ CLI Options (most used)

```
--wordlist, -w       Path to wordlist (one term per line)
--max-lines, -m      Max lines to load from the wordlist (default 200000)
--min-dict-len       Min dictionary word length for substring checks (default 4)
--exact-only         Only exact matches; disable substring checks
--hash-file          Where to store hashes (default ./password_hashes.txt)
--show-hashes        Show the last 3 saved hashes and exit
```

---

## 📚 Wordlists

- Put your files in `./wordlists/` (e.g., `jack_the_reaper.txt`).
- If you keep **SecLists** locally, point `--wordlist` to one of its files.  
  Example: `SecLists/Passwords/Leaked-Databases/rockyou.txt` (or a trimmed copy).

> Tip: For demos, create a trimmed wordlist:  
> `head -n 200000 rockyou.txt > wordlists/jack_the_reaper.txt`

---

## 🧪 Test Harness

Run the sample test script to sanity-check policy behavior:

```bash
bash run_pw_tests.sh
cat test_results.csv
```

You’ll see `accept/reject` vs. expected in a compact CSV.

---

## 🔐 Security Notes

- All checks are **local**; nothing leaves your machine.
- `password_hashes.txt` contains hashed credentials—treat it as sensitive:
  - file permissions are set to `0600` where possible
  - don’t commit this file to Git
- Uploaded wordlists go to `./uploads/` and are used only for that request.

---

## 🧹 What NOT to Commit (and suggested deletions)

**Remove (or don’t commit):**
- `venv/`
- `__pycache__/`
- `password_hashes.txt` (sensitive runtime data)
- `uploads/` (runtime)
- `test_results.csv` (generated output)
- Entire `SecLists/` (huge; reference it in README instead)

## 🛣️ Roadmap Ideas

- Optional **HIBP** breach check (k-anonymity)
- **zxcvbn** entropy feedback in web UI
- Rate limiting & Basic Auth for the web app (LAN demos)
- Package as `pip install pw-enforcer` with console scripts

---

## 🤝 Contributing

PRs welcome! Please:
- keep features off by default if they require network access
- include a short demo + tests under `tests/` or `run_pw_tests.sh`

## 👥 Authors
EL YOUSSOUFI SALMAN – GitHub
Inspired by SEED Labs and GNS3 security simulations

## 📝 License
This project is licensed under the MIT License.

