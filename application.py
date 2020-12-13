import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    current_stock = db.execute("SELECT * from transactions WHERE user_id = :user_id GROUP BY symbol", user_id = session["user_id"])
    total = 0
    consolidate = list()
    user_id = session["user_id"]
    for stock in current_stock:
        update_info = dict()
        check_stock = lookup(stock["symbol"])
        no_shares = db.execute("SELECT SUM(shares) AS shares_sum FROM transactions WHERE user_id = :user_id\
        GROUP BY symbol HAVING symbol = :symbol", user_id = user_id, symbol= stock["symbol"])
        total_shares = no_shares[0]["shares_sum"]
        update_info["name"] = check_stock["name"]
        update_info["symbol"] = check_stock["symbol"]
        update_info["shares"] = total_shares
        update_info["price"] = usd(check_stock["price"])
        total_value = (check_stock["price"]) * update_info["shares"]
        update_info["total"] = usd(total_value)
        consolidate.append(update_info)
        total = total + total_value
    money = db.execute("SELECT cash from users WHERE id = :id", id = user_id)
    grand_total = float(money[0]["cash"]) + total
    return render_template("index.html", consolidate = consolidate, cash = usd(money[0]["cash"]), grand_total = usd(grand_total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("Must enter stock symbol", 400)
        elif not request.form.get("shares"):
            return apology("Must enter shares", 400)
        elif int(request.form.get("shares")) < 1:
            return apology("Must enter positive integer", 400)
        check = lookup(request.form.get("symbol"))
        if not check:
            return apology("Invalid symbol", 400)
        symbol = request.form.get("symbol")
        shares = float(request.form.get("shares"))
        #check = lookup(symbol)
        price = float(check["price"])
        total = shares * price
        user_id = session["user_id"]
        money = db.execute("SELECT cash FROM users where id = :id", id = session["user_id"])
        cash = float(money[0]["cash"])
        if cash < total:
            return apology("Not enough balance", 400)
        else:
            balance = cash - total
            db.execute("INSERT INTO transactions (user_id, stock_name, symbol, shares, price, total) \
            VALUES (:user_id, :stock_name, :symbol, :shares, :price, :total)", user_id = session["user_id"],
            stock_name = check["name"], symbol = check["symbol"], shares = shares, price = check["price"], total = total)
            db.execute("UPDATE users set cash = :balance WHERE id= :user_id", balance=balance, user_id=user_id)
            flash("Stock Bought")
            return redirect("/")
    else:
        return render_template("/buy.html")


@app.route("/history")
@login_required
def history():
    user_id = session["user_id"]
    transactions = db.execute("SELECT * from transactions WHERE user_id= :user_id", user_id = user_id)
    for stock in transactions:
        stock["price"] = usd(stock["price"])
    return render_template("history.html", transactions=transactions)


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

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
    if request.method == "GET":
        return render_template("quote.html")
    else:
        if not request.form.get("symbol"):
            return apology("No information on the stock")
        symbol = request.form.get("symbol")
        check = lookup(symbol)
        if not symbol:
            return apology("Incorrect symbol")
        elif not check:
            return apology("No information on the stock")
        else:
            check["price"] = usd(check["price"])
            return render_template("quoted.html", stock = check)
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    elif request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not username:
            return apology("must provide username", 400)
        elif db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username")):
            return apology("Username already exist", 400)
        elif not password:
            return apology("must provide password", 400)
        elif  not confirmation:
            return apology("must re-enter password", 400)
        elif password != confirmation:
            return apology("password must equal re-enter passward", 400)
        else:
            hash_value = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
            db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username = username, hash = hash_value)
            flash("Account Created")
        return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    user_id = session["user_id"]
    current_stock = db.execute("SELECT symbol FROM transactions WHERE user_id = :user_id GROUP BY symbol", user_id=user_id)
    if request.method == "GET":
        stock_list = list()
        for stocks in current_stock:
            stock_list.append(stocks["symbol"])
        return render_template("sell.html", stock_list = stock_list)
    else:
        if request.form.get("symbol") == "symbol":
            return apology("Must enter stock symbol", 400)
        elif not request.form.get("shares"):
            return apology("Must enter number of shares", 400)
        shares = float(request.form.get("shares"))
        rows = db.execute("SELECT symbol, SUM(shares) AS shares_sum FROM transactions\
        WHERE user_id = :user_id GROUP BY symbol HAVING shares_sum > 0", user_id = user_id)
        for row in rows:
            if row["symbol"] == request.form.get("symbol"):
                if row["shares_sum"] < sell:
                    return apology("Not enough shares to sell", 400)
        else:
            check = lookup(request.form.get("symbol"))
            symbol = request.form.get("symbol")
            price = float(check["price"])
            total = -shares * price
            cash = db.execute("SELECT cash FROM users where id = :id", id = session["user_id"])
            balance = cash[0]["cash"] - total
            db.execute("INSERT INTO transactions (user_id, stock_name, symbol, shares, price, total) \
            VALUES (:user_id, :stock_name, :symbol, :shares, :price, :total)", user_id = session["user_id"],
            stock_name = check["name"], symbol = check["symbol"], shares = -shares, price = check["price"], total = total)
            db.execute("UPDATE users set cash = :balance WHERE id= :user_id", balance=balance, user_id=user_id)
            flash("Sold")
            return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
