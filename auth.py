"""
NetScan Pro - Authentication Module
Provides login/logout routes and login_required decorator.
"""

import os
from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, session, flash

auth = Blueprint("auth", __name__)

# Credentials — override via environment variables in production
ADMIN_USERNAME = os.environ.get("NETSCAN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("NETSCAN_PASS", "admin123")


def login_required(f):
    """Decorator: redirect to login page if user is not authenticated."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("auth.login", next=request.url))
        return f(*args, **kwargs)
    return decorated


@auth.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["logged_in"] = True
            session["username"] = username
            next_url = request.args.get("next") or url_for("index")
            return redirect(next_url)
        else:
            error = "Invalid username or password."
    return render_template("login.html", error=error)


@auth.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
