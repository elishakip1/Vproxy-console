from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

# Simple HTML template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Proxy Checker</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>🚀 Proxy Checker</h1>
        <div class="alert alert-success">
            <h4>Success! Application is working on Vercel.</h4>
            <p>Basic Flask application is now running correctly.</p>
        </div>
        <div class="card">
            <div class="card-body">
                <h5 class="card-title">Next Steps:</h5>
                <ul>
                    <li>Home page is working ✓</li>
                    <li>Admin panel: <a href="/admin">/admin</a></li>
                    <li>Static files are served</li>
                </ul>
            </div>
        </div>
    </div>
</body>
</html>
"""

ADMIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>🔐 Admin Panel</h1>
        <p>Admin panel is working correctly!</p>
        <a href="/" class="btn btn-primary">← Back to Home</a>
    </div>
</body>
</html>
"""

@app.route("/")
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route("/admin")
def admin():
    return render_template_string(ADMIN_TEMPLATE)

@app.route("/test")
def test():
    return {"status": "success", "message": "API is working!"}

# Vercel requires this
def handler(request, context):
    return app(request, context)

if __name__ == "__main__":
    app.run(debug=True)
