import os
import sys

# Add the parent directory to sys.path so it can find app.py
path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if path not in sys.path:
    sys.path.append(path)

# Import the actual Flask app object from app.py
from app import app

# Vercel's Python runtime requires a variable named 'app' 
# or a variable that is an instance of a WSGI app.
app = app
