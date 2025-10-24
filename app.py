from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

# Simple HTML templates as strings to avoid file issues
INDEX_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Proxy Checker</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>Proxy Checker</h1>
        <p>Application is working! Basic functionality is ready.</p>
        <a href="/admin" class="btn btn-primary">Admin Panel</a>
    </div>
</body>
</html>
"""

ADMIN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>Admin Panel</h1>
        <p>Admin panel is working!</p>
        <a href="/" class="btn btn-secondary">Back to Home</a>
    </div>
</body>
</html>
"""

ERROR_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Error</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <div class="alert alert-danger">
            <h4>Error</h4>
            <p>{{ error }}</p>
            <a href="/" class="btn btn-primary">Home</a>
        </div>
    </div>
</body>
</html>
"""

@app.route("/")
def index():
    try:
        return render_template_string(INDEX_HTML)
    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route("/admin")
def admin():
    try:
        return render_template_string(ADMIN_HTML)
    except Exception as e:
        return render_template_string(ERROR_HTML, error=str(e))

@app.errorhandler(404)
def not_found(e):
    return render_template_string(ERROR_HTML, error="Page not found"), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template_string(ERROR_HTML, error=str(e)), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
