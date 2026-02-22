from flask import Flask, request
import sys
import os

# পাথ সেটআপ
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from app import app
    print("✅ App imported successfully")
except Exception as e:
    print(f"❌ Error importing app: {e}")
    import traceback
    traceback.print_exc()
    
    # Fallback app
    app = Flask(__name__)
    
    @app.route('/')
    def home():
        return f"Error loading app: {str(e)}"
    
    @app.route('/debug')
    def debug():
        return f"Python path: {sys.path}"

# Vercel-এর জন্য handler ফাংশন (সঠিক নাম)
def handler(event, context):
    """Vercel Python Runtime handler"""
    return app