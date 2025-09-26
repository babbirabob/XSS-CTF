# app.py -- one-level "advanced" stored XSS CTF (educational use only)
from flask import Flask, request, redirect, render_template_string, url_for
from markupsafe import escape

app = Flask(__name__)
# In-memory "database" of comments for the demo (reset on restart)
COMMENTS = []
# The flag (players must execute JS to read it from /me)
FLAG = "CTF{advanced_stored_xss_2025}"

# Very naive sanitizer: removes literal <script> tags only (intentionally vulnerable)
def naive_sanitize(s: str) -> str:
    return s.replace("<script>", "").replace("</script>", "")

@app.route("/")
def index():
    # Show comment form and list of comments
    comments_html = "\n".join(f"<div class='comment'>{c}</div>" for c in COMMENTS)
    page = f"""
    <h1>Mini Forum — leave a comment</h1>
    <form action="{url_for('post_comment')}" method="post">
      <input name="name" placeholder="name" required>
      <br><textarea name="comment" placeholder="your comment" rows="4" cols="40" required></textarea>
      <br><button>Post Comment</button>
    </form>
    <hr>
    <h2>Comments</h2>
    <div id="comments">{comments_html}</div>
    <p>Tip: test what `<script>alert(1)</script>` does.</p>
    """
    return render_template_string(page)

@app.route("/post", methods=["POST"])
def post_comment():
    name = request.form.get("name", "anon")[:50]
    comment = request.form.get("comment", "")[:1000]
    # intentionally naive sanitize
    safe_name = naive_sanitize(escape(name))
    safe_comment = naive_sanitize(comment)  # do NOT escape here to keep vulnerability visible
    # store the comment as raw HTML (this is the intended vulnerability)
    COMMENTS.append(f"<strong>{safe_name}</strong>: {safe_comment}")
    return redirect(url_for("index"))

@app.route("/me")
def me():
    # The flag is only in JS — not visible in plain HTML. Players must run JS to read it.
    page = f"""
    <h1>Your Profile</h1>
    <p>This page stores a secret in a JavaScript variable (not printed in the HTML).</p>
    <script>
      // secret only accessible to scripts running in the page context
      const secret = "{FLAG}";
      // expose under window for convenience during the challenge
      window.FLAG = secret;
      // Note: we do NOT print the flag in the DOM.
    </script>
    <p>Flag is stored in JavaScript. If an injected script runs here it can read <code>window.FLAG</code>.</p>
    """
    return render_template_string(page)

@app.route("/exfil", methods=["GET"])
def exfil():
    # a simple endpoint that an attacker could use to exfiltrate data
    data = request.args.get("data", "")
    # For demo purposes we print exfiltrated data in server logs and show a short page.
    print("[exfil] received:", data)
    return f"Received (logged): {escape(data)[:200]}"

if __name__ == "__main__":
    # Bind to localhost only
    app.run(host="127.0.0.1", port=5000)
