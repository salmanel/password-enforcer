# pw_core.py
import os, re, unicodedata

# Hashing: Argon2 preferred, bcrypt fallback
try:
    from argon2 import PasswordHasher
    _HAS_ARGON2 = True
    PH = PasswordHasher(time_cost=2, memory_cost=102400)
except Exception:
    _HAS_ARGON2 = False
    import bcrypt

COMMON_PASSWORDS = {"123456","password","qwerty","admin","letmein","12345678","111111"}
DEFAULT_MAX_WORDLIST_LINES = 200_000
DEFAULT_MIN_DICT_LEN = 4

def normalize_text(s: str) -> str:
    return unicodedata.normalize("NFKC", s or "").strip()

def check_strength(password: str) -> int:
    score = 0
    if len(password) >= 8: score += 1
    if len(password) >= 12: score += 1
    if re.search(r"[A-Z]", password): score += 1
    if re.search(r"[a-z]", password): score += 1
    if re.search(r"[0-9]", password): score += 1
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\",.<>/?\\|`~]", password): score += 1
    return score

def meets_regex_policy(password: str) -> bool:
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
    return bool(re.match(pattern, password))

def load_wordlist(path: str, max_lines: int = DEFAULT_MAX_WORDLIST_LINES) -> set:
    if not path or path.endswith(".gz") or not os.path.isfile(path):
        return set()
    wordset = set()
    with open(path, "r", encoding="latin-1", errors="ignore") as fh:
        for i, line in enumerate(fh):
            if max_lines and i >= max_lines: break
            w = line.strip().lower()
            if w: wordset.add(w)
    return wordset

def contains_dictionary_word(password: str, wordset: set, min_len: int, exact_only: bool) -> bool:
    if not wordset: return False
    p = password.lower()
    if p in wordset:  # exact
        return True
    if exact_only:    # substring off
        return False
    for w in wordset:
        if len(w) >= min_len and w in p:
            return True
    return False

def validate_policy(password: str, username: str, wordset: set = None,
                    min_dict_len: int = DEFAULT_MIN_DICT_LEN, exact_only: bool = False):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if username and username.strip() and username.lower() in password.lower():
        return False, "Password must not contain the username."
    if password.lower() in COMMON_PASSWORDS:
        return False, "Password is too common."
    if wordset and contains_dictionary_word(password, wordset, min_dict_len, exact_only):
        return False, "Password contains dictionary word(s)."
    if not meets_regex_policy(password):
        return False, "Password must include uppercase, lowercase, digit, and symbol."
    return True, "Password meets all requirements."

def hash_password(password: str) -> str:
    if _HAS_ARGON2:
        return PH.hash(password)
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")
