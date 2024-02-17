import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        currentUser = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        ticker = lookup(request.form.get('symbol'))
        quantity = request.form.get('shares')
        date = datetime.now()
        type = "BUY"

        print(ticker)
        if ticker == None:
            return render_template("buy.html", placeholder = "INVALID TICKER")

        if currentUser[0]["cash"] < (ticker.get('price') * float(quantity)):
            return apology("not enough cash", 403)

        symbolValue = lookup(request.form.get("symbol"))
        rows = db.execute("INSERT INTO purchaselog (user, ticker, price, date, quantity, type) VALUES (?)", (session["user_id"], ticker["symbol"], symbolValue.get('price'), date, quantity, type))
        dbCheck = []
        dbCheck.append(db.execute("SELECT * FROM usersportfolio WHERE ticker = ? AND user = ?", ticker["symbol"], session["user_id"]))

        if len(dbCheck[0]) != 0:

            dbQuantity = db.execute("SELECT quantity FROM usersportfolio WHERE ticker = ? AND user = ?", ticker["symbol"], session["user_id"])
            dictQuantity = dbQuantity[0]
            current_quantity = dictQuantity.get("quantity")

            new_quantity = int(current_quantity) + int(quantity)

            currentCash = db.execute("SELECT cash FROM users WHERE id = (?)", session["user_id"])

            cashUpdate  = (currentCash[0].get("cash")) - (int(ticker.get('price')) * int(quantity))

            rows = db.execute("UPDATE usersportfolio SET quantity = (?) WHERE ticker = (?) AND user = (?)", new_quantity, ticker["symbol"], session["user_id"])
            db.execute("UPDATE users SET cash = (?) WHERE id = (?)", cashUpdate, session["user_id"])

        else:

            price = int(quantity) * int(ticker.get('price'))

            currentCash = db.execute("SELECT cash FROM users WHERE id = (?)", session["user_id"])

            cashUpdate  = (currentCash[0].get("cash")) - (int(ticker.get('price')) * int(quantity))

            rows = db.execute("INSERT INTO usersportfolio (user, price, quantity, ticker) VALUES (?, ?, ?, ?)", session["user_id"], symbolValue.get('price'), quantity, ticker["symbol"])
            db.execute("UPDATE users SET cash = (?) WHERE id = (?)", cashUpdate, session["user_id"])


        return redirect("/")

    if request.method == "GET":
        return render_template("buy.html", placeholder = "Ticker")
    #return apology("TODO")


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """show users portfolio"""

    rows = db.execute("SELECT * FROM usersportfolio WHERE user == ?", session["user_id"])

    if request.method == "GET":
        if not rows:
            return render_template("index.html")
        else:
            return render_template("indexPortfolio.html", portfolio = rows, currentValue = lookup(rows[0]["ticker"]))

    if request.method == "POST":
        if not rows:
            return render_template("index.html")
        else:
            i = int(request.form.get("page"))

            if i >= len(rows):
                return render_template("index.html")
            else:
                return render_template("indexPortfolio.html", portfolio = rows)

    #return apology("TODO")


@app.route("/history")
@login_required
def history():
    usershistory = db.execute("SELECT * FROM purchaselog WHERE user = (?)", session["user_id"])

    return render_template("history.html", usershistory = usershistory)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    return render_template("quote.html")

    #return apology("TODO")

@app.route("/quoted", methods=["POST"])
@login_required
def quoted():
    """Get stock quote."""

    ticker = request.form.get("symbol")
    quoteValue = lookup(ticker)

    return render_template("quoted.html", quote = quoteValue.get('price'))

    #return apology("TODO")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

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

        # Add username and password to db
        username = request.form.get("username")
        hash = request.form.get("password")


        rows = db.execute("INSERT INTO users(username, hash) VALUES(?, ?)", username, generate_password_hash(hash))

        return render_template("login.html")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        currentTicker = request.form.get("symbol")
        ticker = lookup(request.form.get('symbol'))
        quantity = request.form.get("shares")
        date = datetime.now()
        type = "SELL"

        existingQuantity = [0]
        existingQuantity = db.execute("SELECT quantity FROM usersportfolio WHERE ticker = (?) AND user = (?)", currentTicker, session["user_id"])
        if existingQuantity[0] == 0:
            lsQuantity = existingQuantity[0]
        shareQuantity = lsQuantity.get("quantity")

        newQuantity = int(shareQuantity) - int(quantity)

        currentCash = db.execute("SELECT cash FROM users WHERE id = (?)", session["user_id"])

        cashUpdate  = (currentCash[0].get("cash")) + (int(ticker.get('price')) * int(quantity))

        if int(quantity) >= int(shareQuantity):
            db.execute("DELETE FROM usersportfolio WHERE ticker = (?) AND user = (?)", currentTicker, session["user_id"])
            db.execute("UPDATE users SET cash = (?) WHERE id = (?)", cashUpdate, session["user_id"])

        elif int(quantity) < int(shareQuantity):
            db.execute("UPDATE usersportfolio SET quantity = (?) WHERE ticker = (?) AND user = (?)", newQuantity, currentTicker, session["user_id"])
            db.execute("UPDATE users SET cash = (?) WHERE id = (?)", cashUpdate, session["user_id"])

        rows = db.execute("INSERT INTO purchaselog (user, ticker, price, date, quantity, type) VALUES (?)", (session["user_id"], currentTicker, ticker.get('price'), date, quantity, type))

        return redirect("/")

    else:
        return render_template("sell.html")

