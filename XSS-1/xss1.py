# app.py — minimal reflected XSS challenge (for local lab use only)
from flask import Flask, request, render_template_string

app = Flask(__name__)
FLAG = "CTF{easy_reflected_xss_2025}"

@app.route("/")
def index():
    return '''
    <h1>Mini Search (Reflected XSS)</h1>
    <form action="/search" method="get">
      <input name="q" placeholder="search...">
      <button>Search</button>
    </form>
    <p>Try entering something in the search box.</p>
    '''

@app.route("/search")
def search():
    q = request.args.get("q", "")
    # intentionally vulnerable: user input is reflected unescaped
    html = f"""
    <h2>Results for: {q}</h2>
    <div>Result: {q}</div>
    <p>If your script runs in this page you can fetch the flag from <code>/flag</code>.</p>
    """
    return render_template_string(html)

@app.route("/flag")
def flag():
    # Simple flag endpoint — only for lab
    return FLAG

if __name__ == "__main__":
    # bind to localhost only
    app.run(host="127.0.0.1", port=5000)
