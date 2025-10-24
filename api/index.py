from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "🚀 Proxy Checker is working on Vercel!"

@app.route("/admin")
def admin():
    return "🔐 Admin Panel is working!"

@app.route("/test")
def test():
    return {"status": "success", "message": "API endpoint working"}

def handler(request, context):
    return app(request, context)

if __name__ == "__main__":
    app.run()
