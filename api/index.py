from flask import Flask, request, jsonify, session, redirect, url_for, render_template
import sys
import os

# মূল app.py থেকে ইম্পোর্ট করার জন্য পাথ যোগ করা
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app as flask_app

# Vercel-এর জন্য handler ফাংশন
def handler(event, context):
    return flask_app