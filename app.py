from datetime import timedelta
import logging, secrets, sqlite3, time
from functools import wraps
from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config.update(SECRET_KEY="local-dev-key-change-in-production", SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=False,
                  PERMANENT_SESSION_LIFETIME=timedelta(minutes=30), MAX_CONTENT_LENGTH=2*1024*1024)
DATABASE="auth_lab.db"; LOGIN_LIMIT=5; LOGIN_WINDOW=60; login_attempts={}
logging.basicConfig(filename="auth_security.log", level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

def get_db():
    if "db" not in g:
        g.db=sqlite3.connect(DATABASE); g.db.row_factory=sqlite3.Row
    return g.db
@app.teardown_appcontext
def close_db(exception=None):
    db=g.pop("db",None)
    if db: db.close()
def init_db():
    db=get_db(); db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL)"); db.commit()
def csrf_token():
    if "_csrf_token" not in session: session["_csrf_token"]=secrets.token_urlsafe(32)
    return session["_csrf_token"]
app.jinja_env.globals["csrf_token"]=csrf_token
def validate_csrf():
    supplied=request.form.get("_csrf_token",""); expected=session.get("_csrf_token","")
    if not supplied or not expected or not secrets.compare_digest(supplied,expected):
        logging.warning("CSRF validation failed from %s",request.remote_addr); abort(400,description="Invalid CSRF token.")
def validate_username(username): return bool(username) and 3<=len(username)<=32 and username.replace("_","").isalnum()
def validate_password(password): return bool(password) and 8<=len(password)<=128
def rate_limited(ip):
    now=time.time(); attempts=[t for t in login_attempts.get(ip,[]) if now-t<LOGIN_WINDOW]; login_attempts[ip]=attempts; return len(attempts)>=LOGIN_LIMIT
def record_failed_login(ip): login_attempts.setdefault(ip,[]).append(time.time())
def login_required(view):
    @wraps(view)
    def wrapped(*args,**kwargs):
        if "user_id" not in session: flash("Please log in to continue."); return redirect(url_for("login"))
        return view(*args,**kwargs)
    return wrapped
@app.before_request
def make_session_permanent():
    if "user_id" in session: session.permanent=True
@app.route("/")
def index(): return render_template("index.html")
@app.route("/register",methods=["GET","POST"])
def register():
    if request.method=="POST":
        validate_csrf(); username=request.form.get("username","").strip(); password=request.form.get("password","")
        if not validate_username(username): flash("Username must be 3–32 characters and use letters, numbers, or underscores."); return render_template("register.html"),400
        if not validate_password(password): flash("Password must be 8–128 characters."); return render_template("register.html"),400
        try:
            get_db().execute("INSERT INTO users (username,password_hash) VALUES (?,?)",(username,generate_password_hash(password))); get_db().commit()
        except sqlite3.IntegrityError:
            flash("Registration could not be completed with those details."); return render_template("register.html"),400
        logging.info("User registration completed for username=%s",username); flash("Registration successful. Please log in."); return redirect(url_for("login"))
    return render_template("register.html")
@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        validate_csrf(); ip=request.remote_addr or "unknown"
        if rate_limited(ip): logging.warning("Login rate limit triggered from %s",ip); flash("Too many login attempts. Please wait one minute."); return render_template("login.html"),429
        username=request.form.get("username","").strip(); password=request.form.get("password",""); user=None
        if validate_username(username): user=get_db().execute("SELECT id,username,password_hash FROM users WHERE username=?",(username,)).fetchone()
        if not user or not check_password_hash(user["password_hash"],password):
            record_failed_login(ip); logging.warning("Failed login attempt from %s",ip); flash("Invalid username or password."); return render_template("login.html"),401
        login_attempts.pop(ip,None); session.clear(); session["user_id"]=user["id"]; session["username"]=user["username"]; session.permanent=True; session["_csrf_token"]=secrets.token_urlsafe(32); logging.info("Successful login for username=%s",user["username"]); return redirect(url_for("dashboard"))
    return render_template("login.html")
@app.route("/dashboard")
@login_required
def dashboard(): return render_template("dashboard.html",username=session.get("username"))
@app.route("/logout",methods=["POST"])
@login_required
def logout():
    validate_csrf(); username=session.get("username","unknown"); session.clear(); logging.info("Logout completed for username=%s",username); flash("You have been logged out."); return redirect(url_for("login"))
@app.route("/health")
def health(): return {"status":"ok"}
if __name__=="__main__":
    with app.app_context(): init_db()
    app.run(debug=True)
