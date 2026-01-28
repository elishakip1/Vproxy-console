import sys
import os

# Add the parent directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the main app
from app import app

# Vercel serverless function handler
def handler(request, response):
    # This is the Vercel serverless function handler
    return app(request, response)
