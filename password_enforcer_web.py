#!/usr/bin/env python3
"""
Styled PW Enforcer web UI for password_lab
- Show/hide password fixed
- Logo + version badge
- File upload for wordlist (uploads/)
- NEW: Read-only view of password hash file (first N lines)
"""
import os
import argparse
import logging
import threading
import time
import webbrowser
import html
from flask import Flask, request, render_template_string, redirect, url_for
from werkzeug.utils import secure_filename

# Local core helpers (adjust import if your core file name differs)
from pw_core import normalize_text, validate_policy, check_strength, load_wordlist, hash_password

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("pw_web")

VERSION = "v1.0.0"
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# safety limit when showing hash file
MAX_HASH_LINES_SHOW = 500

TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PW Enforcer • Local</title>
<style>
:root{--bg:#0f172a;--card:#0b1220;--muted:#94a3b8;--text:#e5e7eb;--accent:#4f46e5;--border:#1f2937}
*{box-sizing:border-box}html,body{height:100%}body{margin:0;background:radial-gradient(1200px 600px at -10% -10%, #15213b 0, transparent 60%), radial-gradient(800px 500px at 120% 0, #1a2440 0, transparent 55%),var(--bg);color:var(--text);font:16px/1.5 system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, "Helvetica Neue", Arial}
.container{max-width:1000px;margin:0 auto;padding:24px}
.header{display:flex;align-items:center;justify-content:space-between;background:linear-gradient(135deg, rgba(79,70,229,.12), rgba(34,197,94,.07));border:1px solid var(--border);border-radius:12px;padding:12px 16px}
.brand{display:flex;gap:12px;align-items:center}
.logo{width:40px;height:40px;display:inline-block}
.brand h1{margin:0;font-size:18px}
.version{background:#0b1220;border:1px solid var(--border);padding:6px 10px;border-radius:999px;font-size:13px;color:var(--muted)}
.grid{display:grid;grid-template-columns:1fr 380px;gap:16px;margin-top:16px}
@media (max-width:900px){.grid{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:16px}
label{display:block;font-size:13px;color:var(--muted);margin:10px 0 6px}
input[type=text],input[type=password],input[type=number],input[type=file]{width:100%;background:#08101a;color:var(--text);border:1px solid var(--border);border-radius:8px;padding:8px 10px}
.row{display:flex;gap:8px;align-items:center}
.small{font-size:12px;color:var(--muted)}
.btn{display:inline-flex;align-items:center;gap:8px;background:linear-gradient(180deg,var(--accent),#4338ca);color:white;padding:8px 12px;border:none;border-radius:8px;cursor:pointer}
.btn.secondary{background:#07101a;color:var(--text);border:1px solid var(--border)}
.meter{height:10px;background:#07101a;border:1px solid var(--border);border-radius:999px;overflow:hidden}
.meter>span{display:block;height:100%;width:0%;transition:width .25s}
.meter.ok>span{background:linear-gradient(90deg,#22c55e,#16a34a)}.meter.mid>span{background:linear-gradient(90deg,#f59e0b,#d97706)}.meter.bad>span{background:linear-gradient(90deg,#ef4444,#dc2626)}
.banner{border-radius:8px;padding:10px;margin-top:12px;border:1px solid var(--border)}
.banner.ok{background:#052e1a}.banner.err{background:#2a0f12}
.prewrap{white-space:pre-wrap; word-break:break-word; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; font-size:12px; background:#07101a; border:1px solid var(--border); padding:10px; border-radius:8px; margin-top:8px}
.footer{margin-top:12px;color:var(--muted);font-size:12px}
</style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="brand">
        <svg class="logo" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
          <defs><linearGradient id="g" x1="0" x2="1"><stop offset="0" stop-color="#6366f1"/><stop offset="1" stop-color="#22c55e"/></linearGradient></defs>
          <rect rx="18" ry="18" width="100" height="100" fill="#08101a"/>
          <path d="M30 55 Q 45 20 70 55" stroke="url(#g)" stroke-width="8" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
          <circle cx="50" cy="70" r="8" fill="url(#g)"/>
        </svg>
        <div>
          <h1>PW Enforcer</h1>
          <div class="small">Local password policy & dictionary checks</div>
        </div>
      </div>
      <div class="version">{{version}}</div>
    </div>

    <div class="grid">
      <div class="card">
        <h2>Check a Password</h2>
        <form method="post" action="/check" id="pwform" enctype="multipart/form-data">
          <label>Username</label>
          <input type="text" name="username" id="username" placeholder="e.g. sely">

          <label>Password</label>
          <div class="row">
            <input type="password" name="password" id="password" placeholder="Type a candidate password" autocomplete="new-password">
            <button type="button" class="btn secondary" id="toggle">Show</button>
          </div>
          <div class="meter bad" id="meter"><span></span></div>
          <div class="small" id="scoreLine">Score: 0 / 6</div>

          <hr>

          <label>Upload a wordlist (optional, used for this check)</label>
          <input type="file" name="wordlist_file" accept=".txt">

          <label>Or wordlist path (optional)</label>
          <input type="text" name="wordlist_path" value="{{wordlist_path}}">

          <div class="row" style="margin-top:8px">
            <div style="flex:1">
              <label>Max lines</label>
              <input type="number" name="max_lines" value="{{max_lines}}">
            </div>
            <div style="flex:1">
              <label>Min dict len</label>
              <input type="number" name="min_dict_len" value="{{min_dict_len}}">
            </div>
          </div>

          <label class="small" style="margin-top:8px">
            <input type="checkbox" name="exact_only" {% if exact_only %}checked{% endif %}> Exact match only (disable substring checks)
          </label>

          <label>Hash file (local)</label>
          <input type="text" name="hash_file" value="{{hash_file}}">

          <div style="margin-top:12px">
            <button class="btn" type="submit">Check & Save Hash</button>
            <button class="btn secondary" type="button" id="resetBtn">Reset</button>
            <div class="small" style="margin-top:8px">All processing is local. Uploaded wordlists are stored under <span class="small mono">uploads/</span>.</div>
          </div>
        </form>

        <hr>

        <!-- Show hashes form (separate) -->
        <h3>View saved password hashes</h3>
        <form method="post" action="/hashes" id="hashForm">
          <label>Hash file to view</label>
          <input type="text" name="hash_file" value="{{hash_file}}">
          <div style="margin-top:8px">
            <button class="btn secondary" type="submit">Show hashes (read-only)</button>
            <span class="small" style="margin-left:8px;color:var(--muted)">Limited to first {{max_hash_lines}} lines for safety</span>
          </div>
        </form>

      </div>

      <div class="card">
        <h2>Status</h2>
        <div class="small">Wordlist: <span class="mono">{{wordlist_path or 'None'}}</span></div>

        {% if result %}
          <div class="banner {% if accepted %}ok{% else %}err{% endif %}">
            <div><strong>{{ 'Accepted' if accepted else 'Rejected' }}</strong> — {{message}}</div>
            <div class="small">Server score: <strong>{{score}} / 6</strong>{% if accepted %} • Hash saved to <span class="mono">{{hash_file}}</span>{% endif %}</div>
          </div>
        {% else %}
          <div class="small" style="margin-top:8px;color:var(--muted)">Submit a password to see the server decision here.</div>
        {% endif %}

        <hr>
        <div class="small">Loaded entries: <span class="mono">{{loaded}}</span></div>

        {% if hash_content is defined %}
          <hr>
          <h3>Hashes (first {{shown_lines}} lines)</h3>
          <div class="prewrap">{{hash_content}}</div>
        {% endif %}

      </div>
    </div>

    <div class="footer">© SELY — local demo UI</div>
  </div>
<script>
document.addEventListener('DOMContentLoaded', function(){
  const pwd = document.getElementById('password');
  const meter = document.getElementById('meter');
  const bar = meter ? meter.querySelector('span') : null;
  const line = document.getElementById('scoreLine');
  const toggle = document.getElementById('toggle');
  const resetBtn = document.getElementById('resetBtn');

  // Safer, simpler scoring (no fragile escaping)
  function score(p){
    let s = 0;
    if (!p) return 0;
    if (p.length >= 8)  s++;
    if (p.length >= 12) s++;
    if (/[A-Z]/.test(p)) s++;
    if (/[a-z]/.test(p)) s++;
    if (/[0-9]/.test(p)) s++;
    if (/[^A-Za-z0-9]/.test(p)) s++;   // ← any symbol / punctuation
    return s;
  }

  function render(){
    const s = score(pwd ? pwd.value : "");
    if (bar) {
      const pct = Math.round((s/6)*100);
      bar.style.width = pct + "%";
    }
    if (meter) {
      meter.classList.remove('ok','mid','bad');
      meter.classList.add(s>=5 ? 'ok' : (s>=3 ? 'mid' : 'bad'));
    }
    if (line) line.textContent = "Score: " + s + " / 6";
  }

  if (pwd){
    pwd.addEventListener('input', render);
    render(); // initial
  }

  if (toggle){
    toggle.addEventListener('click', function(ev){
      ev.preventDefault();
      if (!pwd) return;
      pwd.type = (pwd.type === 'password') ? 'text' : 'password';
      toggle.textContent = (pwd.type === 'password') ? 'Show' : 'Hide';
      pwd.focus();
    });
  }

  if (resetBtn){
    resetBtn.addEventListener('click', function(ev){
      ev.preventDefault();
      const form = document.getElementById('pwform');
      if (form) form.reset();
      render();
    });
  }
});
</script>


</body>
</html>
"""

def _save_uploaded_file(file_storage):
    """Save uploaded file and return path (or None)."""
    if not file_storage or file_storage.filename == "":
        return None
    filename = secure_filename(file_storage.filename)
    dest = os.path.join(UPLOAD_DIR, filename)
    file_storage.save(dest)
    return dest

def _read_hash_file_preview(path, max_lines=MAX_HASH_LINES_SHOW):
    """Return an escaped preview (first max_lines lines) and actual lines read."""
    try:
        if not os.path.isfile(path):
            return "(file not found)", 0
        lines = []
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for i, ln in enumerate(fh):
                if i >= max_lines:
                    break
                lines.append(ln.rstrip("\n"))
        escaped = html.escape("\n".join(lines))
        total_read = len(lines)
        # If file had more lines than max_lines, indicate truncation
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            # check quickly whether there are more lines
            for _ in range(max_lines):
                _ = fh.readline()
            rest = fh.readline()
            if rest:
                escaped += html.escape("\n\n... (truncated)\n")
        return escaped, total_read
    except Exception as e:
        log.exception("Failed reading hash file: %s", e)
        return f"(error reading file: {e})", 0

def create_app(default_wordlist=None, max_lines=200000, min_dict_len=4, exact_only=False, hash_file="./password_hashes.txt"):
    app = Flask(__name__)
    app.config["WORDSET"] = load_wordlist(default_wordlist, max_lines) if default_wordlist else set()
    app.config["WORDLIST_PATH"] = default_wordlist or ""
    app.config["MAX_LINES"] = max_lines
    app.config["MIN_DICT_LEN"] = min_dict_len
    app.config["EXACT_ONLY"] = exact_only
    app.config["HASH_FILE"] = hash_file

    @app.route("/", methods=["GET"])
    def index():
        return render_template_string(
            TEMPLATE,
            wordlist_path=app.config["WORDLIST_PATH"],
            max_lines=app.config["MAX_LINES"],
            min_dict_len=app.config["MIN_DICT_LEN"],
            exact_only=app.config["EXACT_ONLY"],
            hash_file=app.config["HASH_FILE"],
            result=None, accepted=False, score=0, message="",
            loaded=len(app.config["WORDSET"]),
            version=VERSION,
            max_hash_lines=MAX_HASH_LINES_SHOW
        )

    @app.route("/check", methods=["POST"])
    def check():
        uploaded = request.files.get("wordlist_file")
        uploaded_path = _save_uploaded_file(uploaded)
        path_field = (request.form.get("wordlist_path","") or app.config["WORDLIST_PATH"]).strip()
        wordlist_path_to_use = uploaded_path or path_field or ""
        max_lines = int(request.form.get("max_lines") or app.config["MAX_LINES"])
        min_dict_len = int(request.form.get("min_dict_len") or app.config["MIN_DICT_LEN"])
        exact_only_flag = bool(request.form.get("exact_only")) or app.config["EXACT_ONLY"]
        hash_file = request.form.get("hash_file") or app.config["HASH_FILE"]

        username = normalize_text(request.form.get("username",""))
        password = normalize_text(request.form.get("password",""))

        wordset = load_wordlist(wordlist_path_to_use, max_lines) if wordlist_path_to_use else app.config["WORDSET"]
        ok, msg = validate_policy(password, username, wordset, min_dict_len, exact_only_flag)
        score = check_strength(password)

        if ok:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(hash_file)), exist_ok=True)
            except Exception:
                pass
            try:
                with open(hash_file, "a", encoding="utf-8") as f:
                    f.write(f"{username}:{hash_password(password)}\n")
                try:
                    os.chmod(hash_file, 0o600)
                except Exception:
                    pass
            except Exception as e:
                log.exception("Failed writing hash: %s", e)

        return render_template_string(
            TEMPLATE,
            wordlist_path=wordlist_path_to_use,
            max_lines=max_lines,
            min_dict_len=min_dict_len,
            exact_only=exact_only_flag,
            hash_file=hash_file,
            result=True, accepted=ok, score=score, message=msg,
            loaded=len(wordset),
            version=VERSION,
            max_hash_lines=MAX_HASH_LINES_SHOW
        )

    @app.route("/hashes", methods=["POST"])
    def hashes():
        # read which file to show (default to configured)
        hash_file = request.form.get("hash_file") or app.config["HASH_FILE"]
        hash_file = hash_file.strip()
        preview, lines_shown = _read_hash_file_preview(hash_file, max_lines=MAX_HASH_LINES_SHOW)
        return render_template_string(
            TEMPLATE,
            wordlist_path=app.config["WORDLIST_PATH"],
            max_lines=app.config["MAX_LINES"],
            min_dict_len=app.config["MIN_DICT_LEN"],
            exact_only=app.config["EXACT_ONLY"],
            hash_file=hash_file,
            result=None, accepted=False, score=0, message="",
            loaded=len(app.config["WORDSET"]),
            version=VERSION,
            hash_content=preview,
            shown_lines=lines_shown,
            max_hash_lines=MAX_HASH_LINES_SHOW
        )

    return app

def main():
    ap = argparse.ArgumentParser(description="PW Enforcer - Local Web UI")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--wordlist", "-w", help="Default wordlist path.")
    ap.add_argument("--max-lines", "-m", type=int, default=200000)
    ap.add_argument("--min-dict-len", type=int, default=4)
    ap.add_argument("--exact-only", action="store_true")
    ap.add_argument("--hash-file", default="./password_hashes.txt")
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    app = create_app(args.wordlist, args.max_lines, args.min_dict_len, args.exact_only, args.hash_file)

    url = f"http://{args.host}:{args.port}/"
    if not args.no_browser:
        threading.Thread(target=lambda: (time.sleep(0.6), webbrowser.open(url)), daemon=True).start()

    app.run(host=args.host, port=args.port, debug=False, threaded=True)

if __name__ == "__main__":
    main()
