import os

from cs50 import SQL
from flask import Flask, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required
from datetime import date

date = date.today()

# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///postit.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/post", methods=["POST"])
def post():
    content = request.form.get("content")
    db.execute("INSERT INTO posts (content, poster_id) VALUES (?, ?)", content, session["user_id"])
    return redirect("/")

@app.route("/")
@login_required
def index():
    load=db.execute("SELECT load FROM users WHERE id = ?",session["user_id"])[0]["load"]
    print(load)
    if load=="following":
        posts = db.execute("SELECT content, datetime, username, displayname FROM posts JOIN users ON users.id=posts.poster_id WHERE poster_id IN (SELECT following_id FROM following WHERE user_id = ?) ORDER BY datetime DESC LIMIT 50",session["user_id"])
        profile = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]
        return render_template("home.html", posts=posts, profile=profile)
    else:
        posts = db.execute("SELECT content, datetime, username, displayname FROM posts JOIN users ON users.id=posts.poster_id ORDER BY datetime DESC LIMIT 50")
        profile = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]
        return render_template("home.html", posts=posts, profile=profile)

@app.route("/search")
def search():
    profile = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]

    return render_template("search.html",profile=profile)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":
        username = request.form.get("username")
        if len(db.execute("SELECT * FROM users WHERE username = ?", username)) > 0:
            return apology("user already exists", 400)
        elif not username:
            return apology("username must be provided", 400)
        password = request.form.get("password")
        if not password:
            return apology("password can't be empty")
        confirmation = request.form.get("confirmation")
        if password != confirmation:
            return apology("confirmation must match password")
        db.execute("INSERT INTO users (username, hash, displayname, datecreated, bio) VALUES(?, ?, ?, ?, ?)",
                   username, generate_password_hash(password), username, date, "hello, i'm using post-it")
        return redirect("/")
    else:
        return render_template("register.html")

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    profile = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]
    return render_template("settings.html",profile=profile)

@app.route("/profile", methods=["GET"])
@login_required
def profile():
    posts = db.execute("SELECT content, datetime, username, displayname FROM posts JOIN users ON users.id=posts.poster_id WHERE id = ? ORDER BY datetime DESC LIMIT 50", session["user_id"])
    profile = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]

    return render_template("profile.html",posts=posts,profile=profile)


# SEARCH FUNCTIONS

@app.route("/searchuser")
def searchuser():
    profile = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]
    username = request.args.get("username")
    results = db.execute("SELECT * FROM users WHERE username LIKE ?", '%' + username + '%')
    followlist = db.execute("SELECT following_id FROM following WHERE user_id = ?", session["user_id"])
    list = []
    for i in followlist:
        list.append(i["following_id"])
    for i in results:
        i["follow_status"] = "unfollow" if i["id"] in list else "follow"
    return render_template("searched_user.html",username=username, profile=profile, results=results)

@app.route("/searchdn")
def searchdn():
    profile = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]
    username = request.args.get("displayname")
    results = db.execute("SELECT * FROM users WHERE displayname LIKE ?", '%' + username + '%')
    followlist = db.execute("SELECT following_id FROM following WHERE user_id = ?", session["user_id"])
    list = []
    for i in followlist:
        list.append(i["following_id"])
    for i in results:
        i["follow_status"] = "unfollow" if i["id"] in list else "follow"
    return render_template("searched_user.html",username=username, profile=profile, results=results)

@app.route("/searchpost")
def searchpost():
    profile = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]
    return apology("search post page not found",profile=profile)

# FOLLOW FUNCTIONS

@app.route("/follow", methods=["POST"])
@login_required
def follow():
    followed = request.form.get("followed_id")
    user_fol = int(db.execute("SELECT following FROM users WHERE id = ?", session["user_id"])[0]["following"])
    user_fol += 1
    fol = int(db.execute("SELECT followers FROM users WHERE id = ?", followed)[0]["followers"])
    fol += 1
    db.execute("UPDATE users SET following = ? WHERE id = ?", user_fol, session["user_id"])
    db.execute("UPDATE users SET followers = ? WHERE id = ?", fol, followed)
    db.execute("INSERT INTO following (user_id, following_id) VALUES (?,?)", session["user_id"], followed)

    return redirect("/search")

@app.route("/unfollow", methods=["POST"])
@login_required
def unfollow():
    followed = request.form.get("followed_id")
    user_fol = int(db.execute("SELECT following FROM users WHERE id = ?", session["user_id"])[0]["following"])
    user_fol -= 1
    fol = int(db.execute("SELECT followers FROM users WHERE id = ?", followed)[0]["followers"])
    fol -= 1
    db.execute("UPDATE users SET following = ? WHERE id = ?", user_fol, session["user_id"])
    db.execute("UPDATE users SET followers = ? WHERE id = ?", fol, followed)
    db.execute("DELETE FROM following WHERE user_id = ? AND following_id = ?", session["user_id"], followed)

    return redirect("/search")

# SETTINGS FUNCTIONS

@app.route("/changedn", methods=["POST"])
@login_required
def changedn():
    dn = request.form.get("displayname")
    db.execute("UPDATE users SET displayname = ? WHERE id = ?",dn,session["user_id"])
    return redirect("/profile")

@app.route("/changebio", methods=["POST"])
@login_required
def changebio():
    bio = request.form.get("bio")
    db.execute("UPDATE users SET bio = ? WHERE id = ?",bio,session["user_id"])
    return redirect("/profile")

@app.route("/changepw", methods=["POST"])
@login_required
def changepw():
    pw = request.form.get("pw")
    db.execute("UPDATE users SET hash = ? WHERE id = ?",generate_password_hash(pw),session["user_id"])
    return redirect("/profile")

@app.route("/setcontent", methods=["POST"])
@login_required
def setcontent():
    value = request.form.get("button")
    db.execute("UPDATE users SET load = ? WHERE id = ?", value, session["user_id"])
    return redirect("/profile")


@app.route("/browse")
def browse():
    return render_template("browse.html")
