# app.py -- "advanced" one-level stored XSS CTF (educational use only)
from flask import Flask, request, redirect, render_template_string, url_for
from markupsafe import escape

app = Flask(__name__)

# In-memory "database" — resets when the app restarts
COMMENTS = []
# The flag (solvers must execute JS in /me to read this)
FLAG = "CTF{adv_xss_level1_2025}"

def naive_sanitize(s: str) -> str:
    """
    Intentionally vulnerable sanitizer:
    removes literal <script> and </script> tokens only (case-sensitive).
    Does NOT escape attributes or other tags.
    """
    return s.replace("<script>", "").replace("</script>", "")

@app.route("/")
def index():
    # comment submission UI + shows all comments
    comments_html = "\n".join(f"<div class='comment'>{c}</div>" for c in COMMENTS)
    page = f"""
    <h1>MiniForum — post a comment</h1>
    <p>This forum attempts to remove <code>&lt;script&gt;</code> tags but is incomplete.</p>
    <form action="{url_for('post_comment')}" method="post">
      <input name="name" placeholder="name" required maxlength="40">
      <br><textarea name="comment" placeholder="your comment" rows="4" cols="50" required maxlength="800"></textarea>
      <br><button>Post</button>
    </form>
    <hr>
    <h2>Recent comments</h2>
    <div id="comments">{comments_html}</div>
    <hr>
    <p>Visit <a href="{url_for('me')}">your profile</a> to see a personal page.</p>
    """
    return render_template_string(page)

@app.route("/post", methods=["POST"])
def post_comment():
    name = request.form.get("name", "anon")[:40]
    comment = request.form.get("comment", "")[:800]
    # intentionally naive sanitizer for the comment text only (keeps vulnerability)
    safe_name = escape(name)
    safe_comment = naive_sanitize(comment)  # do not escape -> vulnerability
    COMMENTS.append(f"<strong>{safe_name}</strong>: {safe_comment}")
    return redirect(url_for("index"))

@app.route("/me")
def me():
    # The flag is kept in JS only (not printed in the HTML)
    # This page also displays the global comment feed (so stored XSS can fire here)
    comments_html = "\n".join(f"<div class='comment'>{c}</div>" for c in COMMENTS)
    page = f"""
    <h1>Your Profile</h1>
    <p>This page stores a secret in a JavaScript variable; the secret is <strong>not</strong> shown in the DOM.</p>

    <script>
      // secret only accessible to scripts running in the page context
      const secret = "{FLAG}";
      // convenient alias for solvers if their script runs
      window.FLAG = secret;
    </script>

    <h2>Comments (shared)</h2>
    <div id="comments">{comments_html}</div>

    <p>If your injected script runs on this page it can read <code>window.FLAG</code>.</p>
    """
    return render_template_string(page)

@app.route("/exfil", methods=["GET"])
def exfil():
    # Simple exfil endpoint — logs the data server-side for teacher visibility.
    data = request.args.get("data", "")
    print("[EXFILTRATED]", data)
    return f"OK (logged): {escape(data)[:200]}"

if __name__ == "__main__":
    # Bind to localhost only (do NOT change to 0.0.0.0 unless you know what you do)
    app.run(host="127.0.0.1", port=5000)
