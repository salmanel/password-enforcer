#!/usr/bin/env python3
"""
Password Policy Enforcer CLI — Styled Version
Features:
  ✅ Prints password strength score table
  ✅ Validates passwords against policy & dictionary
  ✅ Saves hashed passwords locally
  ✅ Shows last 3 hashes (--show-hashes)
"""

import os, sys, io, argparse, getpass, logging
from colorama import Fore, Style, init
from pw_core import load_wordlist, validate_policy, check_strength, hash_password

init(autoreset=True)
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("pw_cli")

VERSION = "v1.0.0"
MAX_HASH_LINES_SHOW = 500

# ==============================
# Score Table (printed at start)
# ==============================
POLICY_TABLE = f"""
{Fore.CYAN}=== PASSWORD STRENGTH SCORE TABLE ==={Style.RESET_ALL}
Each satisfied criterion adds points (max = 6)

| Criterion                               | Points |
|----------------------------------------|:------:|
| Length >= 8 characters                 |  +1    |
| Length >= 12 characters                |  +1    |
| Contains uppercase letter              |  +1    |
| Contains lowercase letter              |  +1    |
| Contains digit                         |  +1    |
| Contains symbol (!@#$%^&* etc.)        |  +1    |

{Fore.YELLOW}A strong password typically scores 5 or 6 points.{Style.RESET_ALL}
"""

# ==============================
# Helper: show last N hashes
# ==============================
def read_last_hash_entries(path: str, count: int = 3):
    """Return last `count` lines of hash file."""
    try:
        if not os.path.isfile(path):
            return "(file not found)", 0
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            data = bytearray()
            lines_found = 0
            pos = size - 1
            while pos >= 0 and lines_found < count:
                fh.seek(pos)
                byte = fh.read(1)
                if byte == b"\n":
                    lines_found += 1
                data.extend(byte)
                pos -= 1
            data.reverse()
            text = data.decode("utf-8", errors="replace").strip()
            return text, min(lines_found, count)
    except Exception as e:
        log.exception("Error reading hash file: %s", e)
        return f"(error reading {path}: {e})", 0

# ==============================
# Helper: append new hash
# ==============================
def append_hash(path, entry):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(entry)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass

# ==============================
# Argument parsing
# ==============================
def parse_args():
    ap = argparse.ArgumentParser(description="Password Policy Enforcer CLI")
    ap.add_argument("--wordlist", "-w", help="Path to wordlist (e.g., ./wordlists/jack_the_reaper.txt)")
    ap.add_argument("--max-lines", "-m", type=int, default=200000, help="Max lines to load from wordlist")
    ap.add_argument("--min-dict-len", type=int, default=4, help="Min dictionary word length")
    ap.add_argument("--hash-file", default="./password_hashes.txt", help="File to store or read hashes")
    ap.add_argument("--show-hashes", action="store_true", help="Show last 3 saved hashes and exit")
    return ap.parse_args()

# ==============================
# Main logic
# ==============================
def main():
    args = parse_args()

    # Always print score table at start
    print(POLICY_TABLE)
    print(Fore.CYAN + f"PW Enforcer CLI {VERSION}" + Style.RESET_ALL)

    # Option 1: show hashes
    if args.show_hashes:
        preview, shown = read_last_hash_entries(args.hash_file, count=3)
        print(Fore.CYAN + f"\n=== Last {shown} entries in {args.hash_file} ===" + Style.RESET_ALL)
        print(preview)
        return

    # Option 2: check password
    print(Fore.CYAN + "\n=== Password Policy Check ===" + Style.RESET_ALL)
    username = input("Enter username: ").strip()
    password = getpass.getpass("Enter password: ").strip()

    # Load dictionary
    wordset = load_wordlist(args.wordlist, max_lines=args.max_lines) if args.wordlist else set()
    print(Fore.GREEN + f"[+] Loaded {len(wordset):,} wordlist entries" + Style.RESET_ALL)

    # Evaluate
    ok, msg = validate_policy(password, username, wordset, args.min_dict_len)
    score = check_strength(password)
    print(Fore.CYAN + f"Score: {score}/6" + Style.RESET_ALL)

    if ok:
        print(Fore.GREEN + "[✓] " + msg + Style.RESET_ALL)
        append_hash(args.hash_file, f"{username}:{hash_password(password)}\n")
        print(Fore.YELLOW + f"Hash saved to {args.hash_file}" + Style.RESET_ALL)
    else:
        print(Fore.RED + "[✗] " + msg + Style.RESET_ALL)


if __name__ == "__main__":
    main()

