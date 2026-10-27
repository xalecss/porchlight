"""Porchlight - volunteers sign up to help seniors in their town. Run: python3 main.py"""
import os
import sqlite3
import uuid
from datetime import datetime
from functools import wraps

from flask import (Flask, g, request, session, redirect, url_for, flash,
                   render_template, send_from_directory, abort)
from jinja2 import DictLoader
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "seniorhelp.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

SENIOR_MIN_AGE = 60
VOLUNTEER_MIN_AGE = 16
MIN_OVERLAP_MINUTES = 30
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024

# ---------------------------------------------------------------- database

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    pw_hash TEXT NOT NULL,
    role TEXT NOT NULL,              -- 'senior' | 'volunteer'
    age INTEGER NOT NULL,
    town TEXT NOT NULL,
    id_file TEXT,
    verified INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    senior_id INTEGER NOT NULL,
    town TEXT NOT NULL,
    address TEXT NOT NULL,
    description TEXT NOT NULL,
    start TEXT NOT NULL,             -- ISO 'YYYY-MM-DDTHH:MM'
    end TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',   -- open | matched | completed | cancelled
    volunteer_id INTEGER,
    sched_start TEXT,
    sched_end TEXT
);
CREATE TABLE IF NOT EXISTS availability (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    volunteer_id INTEGER NOT NULL,
    town TEXT NOT NULL,
    start TEXT NOT NULL,
    end TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL,
    reviewer_id INTEGER NOT NULL,
    reviewee_id INTEGER NOT NULL,
    rating INTEGER NOT NULL,
    comment TEXT,
    UNIQUE(request_id, reviewer_id)
);
"""


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    d = g.pop("db", None)
    if d:
        d.close()


def init_db():
    with sqlite3.connect(DB_PATH) as c:
        c.executescript(SCHEMA)


# ---------------------------------------------------------------- helpers

def overlap(a_start, a_end, b_start, b_end):
    """Return (start, end) of the overlap of two ISO ranges, or None if too short."""
    s, e = max(a_start, b_start), min(a_end, b_end)
    if s >= e:
        return None
    minutes = (datetime.fromisoformat(e) - datetime.fromisoformat(s)).total_seconds() / 60
    return (s, e) if minutes >= MIN_OVERLAP_MINUTES else None


def avg_rating(user_id):
    r = db().execute(
        "SELECT AVG(rating) a, COUNT(*) n FROM reviews WHERE reviewee_id=?", (user_id,)
    ).fetchone()
    return (round(r["a"], 1), r["n"]) if r["n"] else (None, 0)


@app.template_filter("fmt")
def fmt(s):
    return datetime.fromisoformat(s).strftime("%a %b %d, %I:%M %p") if s else ""


app.jinja_env.globals["avg_rating"] = avg_rating


@app.before_request
def load_user():
    g.user = None
    if session.get("uid"):
        g.user = db().execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()


def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not g.user:
            return redirect(url_for("login"))
        return f(*a, **k)
    return w


def verified_required(f):
    @wraps(f)
    @login_required
    def w(*a, **k):
        if g.user["verified"] != 1:
            flash("Your ID hasn't been verified yet. You can do this once an admin approves it.", "err")
            return redirect(url_for("home"))
        return f(*a, **k)
    return w


def role_required(role):
    def deco(f):
        @wraps(f)
        @verified_required
        def w(*a, **k):
            if g.user["role"] != role:
                abort(403)
            return f(*a, **k)
        return w
    return deco


def valid_range(start, end):
    try:
        s, e = datetime.fromisoformat(start), datetime.fromisoformat(end)
    except ValueError:
        return "Please fill in both times."
    if e <= s:
        return "End time must be after start time."
    if s < datetime.now():
        return "Start time must be in the future."
    return None


# ---------------------------------------------------------------- auth

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        f = request.form
        name, email = f["name"].strip(), f["email"].strip().lower()
        role, town = f["role"], f["town"].strip().title()
        try:
            age = int(f["age"])
        except ValueError:
            age = 0
        file = request.files.get("id_photo")

        if role not in ("senior", "volunteer"):
            flash("Pick a role.", "err")
        elif role == "senior" and age < SENIOR_MIN_AGE:
            flash(f"Senior accounts are for ages {SENIOR_MIN_AGE}+.", "err")
        elif role == "volunteer" and age < VOLUNTEER_MIN_AGE:
            flash(f"Volunteers must be at least {VOLUNTEER_MIN_AGE}.", "err")
        elif len(f["password"]) < 6:
            flash("Password must be at least 6 characters.", "err")
        elif not (name and town and email):
            flash("Fill in everything.", "err")
        elif not file or not file.filename:
            flash("Please upload a photo of your ID.", "err")
        else:
            fname = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
            try:
                db().execute(
                    "INSERT INTO users (name,email,pw_hash,role,age,town,id_file) VALUES (?,?,?,?,?,?,?)",
                    (name, email, generate_password_hash(f["password"], method="pbkdf2:sha256"), role, age, town, fname))
                db().commit()
            except sqlite3.IntegrityError:
                flash("That email is already registered.", "err")
                return render_template("register.html")
            file.save(os.path.join(UPLOAD_DIR, fname))
            flash("Account created! An admin will verify your ID, then you're good to go.", "ok")
            return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = db().execute("SELECT * FROM users WHERE email=?",
                         (request.form["email"].strip().lower(),)).fetchone()
        if u and check_password_hash(u["pw_hash"], request.form["password"]):
            session.clear()
            session["uid"] = u["id"]
            return redirect(url_for("home"))
        flash("Wrong email or password.", "err")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------- home / dashboards

@app.route("/")
@login_required
def home():
    u = g.user
    if u["role"] == "senior":
        reqs = db().execute(
            """SELECT r.*, v.name vname FROM requests r
               LEFT JOIN users v ON v.id = r.volunteer_id
               WHERE r.senior_id=? ORDER BY r.start DESC""", (u["id"],)).fetchall()
        reviewed = {r["request_id"] for r in db().execute(
            "SELECT request_id FROM reviews WHERE reviewer_id=?", (u["id"],))}
        return render_template("senior.html", reqs=reqs, reviewed=reviewed)

    av = db().execute("SELECT * FROM availability WHERE volunteer_id=? AND end > ? ORDER BY start",
                      (u["id"], datetime.now().isoformat(timespec="minutes"))).fetchall()
    jobs = db().execute(
        """SELECT r.*, s.name sname FROM requests r JOIN users s ON s.id=r.senior_id
           WHERE r.volunteer_id=? ORDER BY r.sched_start DESC""", (u["id"],)).fetchall()
    reviewed = {r["request_id"] for r in db().execute(
        "SELECT request_id FROM reviews WHERE reviewer_id=?", (u["id"],))}
    return render_template("volunteer.html", av=av, jobs=jobs, reviewed=reviewed)


# ---------------------------------------------------------------- senior actions

@app.route("/request/new", methods=["POST"])
@role_required("senior")
def new_request():
    f = request.form
    err = valid_range(f["start"], f["end"])
    if err:
        flash(err, "err")
    elif not f["description"].strip() or not f["address"].strip():
        flash("Add a description and your address.", "err")
    else:
        town = (f.get("town") or g.user["town"]).strip().title()
        db().execute(
            "INSERT INTO requests (senior_id,town,address,description,start,end) VALUES (?,?,?,?,?,?)",
            (g.user["id"], town, f["address"].strip(), f["description"].strip(), f["start"], f["end"]))
        db().commit()
        flash("Request posted! We'll match you with a volunteer.", "ok")
    return redirect(url_for("home"))


@app.route("/request/<int:rid>/cancel", methods=["POST"])
@role_required("senior")
def cancel_request(rid):
    db().execute("UPDATE requests SET status='cancelled' WHERE id=? AND senior_id=? AND status IN ('open','matched')",
                 (rid, g.user["id"]))
    db().commit()
    return redirect(url_for("home"))


# ---------------------------------------------------------------- volunteer actions

@app.route("/availability/add", methods=["POST"])
@role_required("volunteer")
def add_availability():
    f = request.form
    err = valid_range(f["start"], f["end"])
    if err:
        flash(err, "err")
    else:
        town = (f.get("town") or g.user["town"]).strip().title()
        db().execute("INSERT INTO availability (volunteer_id,town,start,end) VALUES (?,?,?,?)",
                     (g.user["id"], town, f["start"], f["end"]))
        db().commit()
    return redirect(url_for("home"))


@app.route("/availability/<int:aid>/delete", methods=["POST"])
@role_required("volunteer")
def del_availability(aid):
    db().execute("DELETE FROM availability WHERE id=? AND volunteer_id=?", (aid, g.user["id"]))
    db().commit()
    return redirect(url_for("home"))


@app.route("/jobs")
@role_required("volunteer")
def jobs():
    town = (request.args.get("town") or g.user["town"]).strip().title()
    avail = db().execute("SELECT * FROM availability WHERE volunteer_id=? AND town=? AND end > ?",
                         (g.user["id"], town, datetime.now().isoformat(timespec="minutes"))).fetchall()
    open_reqs = db().execute(
        """SELECT r.*, s.name sname FROM requests r JOIN users s ON s.id=r.senior_id
           WHERE r.status='open' AND r.town=? ORDER BY r.start""", (town,)).fetchall()
    matches = []
    for r in open_reqs:
        for a in avail:
            o = overlap(r["start"], r["end"], a["start"], a["end"])
            if o:
                matches.append((r, o))
                break
    return render_template("jobs.html", town=town, matches=matches, has_avail=bool(avail))


@app.route("/jobs/<int:rid>/accept", methods=["POST"])
@role_required("volunteer")
def accept(rid):
    r = db().execute("SELECT * FROM requests WHERE id=? AND status='open'", (rid,)).fetchone()
    if not r:
        flash("Sorry, that job was just taken.", "err")
        return redirect(url_for("jobs"))
    avail = db().execute("SELECT * FROM availability WHERE volunteer_id=? AND town=?",
                         (g.user["id"], r["town"])).fetchall()
    for a in avail:
        o = overlap(r["start"], r["end"], a["start"], a["end"])
        if o:
            cur = db().execute(
                "UPDATE requests SET status='matched', volunteer_id=?, sched_start=?, sched_end=? "
                "WHERE id=? AND status='open'", (g.user["id"], o[0], o[1], rid))
            db().commit()
            if cur.rowcount:
                flash("You're booked! Details are on your dashboard.", "ok")
                return redirect(url_for("home"))
    flash("Your availability doesn't overlap with that job.", "err")
    return redirect(url_for("jobs"))


@app.route("/request/<int:rid>/complete", methods=["POST"])
@role_required("volunteer")
def complete(rid):
    db().execute("UPDATE requests SET status='completed' WHERE id=? AND volunteer_id=? AND status='matched'",
                 (rid, g.user["id"]))
    db().commit()
    flash("Marked complete. Please leave a review!", "ok")
    return redirect(url_for("home"))


# ---------------------------------------------------------------- reviews

@app.route("/review/<int:rid>", methods=["GET", "POST"])
@verified_required
def review(rid):
    r = db().execute("SELECT * FROM requests WHERE id=? AND status='completed'", (rid,)).fetchone()
    if not r or g.user["id"] not in (r["senior_id"], r["volunteer_id"]):
        abort(404)
    other_id = r["volunteer_id"] if g.user["id"] == r["senior_id"] else r["senior_id"]
    other = db().execute("SELECT name FROM users WHERE id=?", (other_id,)).fetchone()
    if request.method == "POST":
        rating = int(request.form["rating"])
        if not 1 <= rating <= 5:
            abort(400)
        try:
            db().execute(
                "INSERT INTO reviews (request_id,reviewer_id,reviewee_id,rating,comment) VALUES (?,?,?,?,?)",
                (rid, g.user["id"], other_id, rating, request.form["comment"].strip()))
            db().commit()
            flash("Review saved. Thank you!", "ok")
        except sqlite3.IntegrityError:
            flash("You already reviewed this one.", "err")
        return redirect(url_for("home"))
    return render_template("review.html", other=other, rid=rid)


# ---------------------------------------------------------------- admin (ID verification)

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST" and "password" in request.form:
        if request.form["password"] == ADMIN_PASSWORD:
            session["admin"] = True
        else:
            flash("Wrong admin password.", "err")
    if not session.get("admin"):
        return render_template("admin_login.html")
    q = lambda v: db().execute("SELECT * FROM users WHERE verified=? ORDER BY id DESC", (v,)).fetchall()
    return render_template("admin.html", pending=q(0), approved=q(1), rejected=q(-1))


@app.route("/admin/set/<int:uid>/<action>", methods=["POST"])
def admin_set(uid, action):
    if not session.get("admin"):
        abort(403)
    if action == "approve":
        db().execute("UPDATE users SET verified=1 WHERE id=?", (uid,))
    elif action == "reject":
        db().execute("UPDATE users SET verified=-1 WHERE id=?", (uid,))
    elif action == "delete":
        u = db().execute("SELECT id_file FROM users WHERE id=?", (uid,)).fetchone()
        if u:
            try:
                os.remove(os.path.join(UPLOAD_DIR, u["id_file"]))
            except OSError:
                pass
            db().execute("DELETE FROM users WHERE id=?", (uid,))
    else:
        abort(400)
    db().commit()
    return redirect(url_for("admin"))


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("admin"))


@app.route("/admin/id/<path:fname>")
def admin_id(fname):
    if not session.get("admin"):
        abort(403)
    return send_from_directory(UPLOAD_DIR, fname)


# ---------------------------------------------------------------- templates

T = {}
T["base.html"] = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Porchlight</title>
<style>
:root{--a:#4f46e5;--b:#7c3aed;--ink:#1e1b4b;--muted:#6b7280;--ok:#059669;--bad:#dc2626}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,sans-serif;color:var(--ink);
background:linear-gradient(135deg,#eef2ff,#fdf2f8,#ecfeff,#eef2ff);background-size:300% 300%;animation:bg 20s ease infinite;min-height:100vh}
@keyframes bg{0%{background-position:0 50%}50%{background-position:100% 50%}100%{background-position:0 50%}}
@keyframes drop{from{transform:translateY(-100%);opacity:0}to{transform:none;opacity:1}}
@keyframes rise{from{transform:translateY(24px);opacity:0}to{transform:none;opacity:1}}
@keyframes pop{from{transform:scale(.9);opacity:0}to{transform:none;opacity:1}}
@keyframes beat{0%,100%{transform:scale(1)}50%{transform:scale(1.18)}}
@keyframes slide{from{transform:translateX(-30px);opacity:0}to{transform:none;opacity:1}}
nav{position:sticky;top:0;z-index:20;display:flex;justify-content:space-between;align-items:center;padding:12px 28px;
background:rgba(255,255,255,.72);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);
border-bottom:1px solid rgba(79,70,229,.12);animation:drop .6s cubic-bezier(.2,.8,.2,1)}
.brand{font-weight:800;font-size:1.3em;text-decoration:none;color:var(--ink);display:flex;align-items:center;gap:8px}
.brand span{display:inline-block;animation:beat 1.8s ease-in-out infinite}
.brand b{background:linear-gradient(90deg,var(--a),var(--b));-webkit-background-clip:text;background-clip:text;color:transparent}
.links{display:flex;align-items:center;gap:6px}
.links a,.who{padding:8px 14px;border-radius:99px;text-decoration:none;color:var(--ink);font-weight:600;position:relative;transition:.25s}
.links a::after{content:"";position:absolute;left:50%;bottom:3px;width:0;height:2px;background:linear-gradient(90deg,var(--a),var(--b));
transition:.3s;transform:translateX(-50%);border-radius:2px}
.links a:hover{background:rgba(79,70,229,.08);transform:translateY(-1px)}
.links a:hover::after{width:60%}
.links a.cta{background:linear-gradient(90deg,var(--a),var(--b));color:#fff;box-shadow:0 4px 14px rgba(79,70,229,.35)}
.links a.cta::after{display:none}
.who{color:var(--muted);font-weight:500;font-size:.9em}
.burger{display:none;background:none;border:0;cursor:pointer;width:42px;height:42px;padding:8px;margin:0;box-shadow:none}
.burger i{display:block;height:3px;margin:5px 0;background:var(--ink);border-radius:3px;transition:.35s}
.burger.open i:nth-child(1){transform:translateY(8px) rotate(45deg)}
.burger.open i:nth-child(2){opacity:0}
.burger.open i:nth-child(3){transform:translateY(-8px) rotate(-45deg)}
@media(max-width:680px){
 .burger{display:block}
 .links{position:absolute;top:100%;left:0;right:0;flex-direction:column;align-items:stretch;background:rgba(255,255,255,.96);
 padding:0 16px;max-height:0;overflow:hidden;transition:max-height .45s ease,padding .45s ease}
 .links.open{max-height:360px;padding:12px 16px}
 .links a,.who{text-align:center}
}
main{max-width:780px;margin:26px auto 60px;padding:0 16px}
h2{font-size:1.5em;margin:26px 0 6px;animation:slide .6s ease both}
.hero{text-align:center;margin:30px 0 10px;animation:rise .7s ease both}
.hero h1{font-size:2.2em;margin:0 0 6px;background:linear-gradient(90deg,var(--a),var(--b),#ec4899);-webkit-background-clip:text;background-clip:text;color:transparent}
.hero p{color:var(--muted);margin:0}
.card{background:rgba(255,255,255,.85);backdrop-filter:blur(8px);border-radius:18px;padding:20px;margin:16px 0;
border:1px solid rgba(255,255,255,.9);box-shadow:0 6px 24px rgba(30,27,75,.08);
opacity:0;animation:rise .6s cubic-bezier(.2,.8,.2,1) forwards;transition:transform .3s,box-shadow .3s}
.card:hover{transform:translateY(-4px);box-shadow:0 14px 34px rgba(79,70,229,.18)}
.card h2{margin-top:0}
label{display:block;margin:14px 0 5px;font-weight:600;font-size:.92em}
input,select,textarea{width:100%;padding:12px 14px;border:2px solid #e5e7eb;border-radius:12px;font-size:1em;background:#fff;
font-family:inherit;transition:border-color .25s,box-shadow .25s,transform .25s}
input:focus,select:focus,textarea:focus{outline:0;border-color:var(--a);box-shadow:0 0 0 4px rgba(79,70,229,.15);transform:translateY(-1px)}
button,.btn{background:linear-gradient(90deg,var(--a),var(--b));color:#fff;border:0;padding:11px 20px;border-radius:12px;font-size:1em;
font-weight:600;cursor:pointer;text-decoration:none;display:inline-block;margin-top:14px;box-shadow:0 4px 14px rgba(79,70,229,.3);
transition:transform .2s,box-shadow .2s,filter .2s}
button:hover,.btn:hover{transform:translateY(-2px);box-shadow:0 8px 20px rgba(79,70,229,.4);filter:brightness(1.06)}
button:active,.btn:active{transform:scale(.97)}
button.red{background:linear-gradient(90deg,#ef4444,#dc2626);box-shadow:0 4px 14px rgba(220,38,38,.3)}
button.green,.btn.green{background:linear-gradient(90deg,#10b981,#059669);box-shadow:0 4px 14px rgba(5,150,105,.3)}
button.grey,.btn.grey{background:linear-gradient(90deg,#6b7280,#4b5563);box-shadow:0 4px 14px rgba(75,85,99,.3)}
.flash{padding:13px 16px;border-radius:14px;margin:12px 0;font-weight:500;animation:slide .5s ease both;transition:opacity .6s,transform .6s}
.flash.ok{background:#d1fae5;color:#065f46;border-left:5px solid var(--ok)}
.flash.err{background:#fee2e2;color:#991b1b;border-left:5px solid var(--bad)}
.tag{font-size:.75em;font-weight:700;text-transform:uppercase;letter-spacing:.05em;padding:4px 12px;border-radius:99px;background:#e5e7eb;display:inline-block;margin-bottom:6px}
.tag.open{background:#dbeafe;color:#1d4ed8;animation:beat 2.4s ease-in-out infinite}
.tag.matched{background:#d1fae5;color:#065f46}.tag.completed{background:#ede9fe;color:#5b21b6}.tag.cancelled{background:#fee2e2;color:#991b1b}
.muted,small{color:var(--muted)}
form.inline{display:inline}form.inline button{margin-top:8px}
p{line-height:1.5}
</style></head><body>
<nav><a class="brand" href="{{ url_for('home') }}"><span>&#128153;</span><b>Porchlight</b></a>
<button class="burger" id="bg" aria-label="menu"><i></i><i></i><i></i></button>
<div class="links" id="lk">
{% if g.user %}<span class="who">{{ g.user.name }} &middot; {{ g.user.role }}</span>
<a href="{{ url_for('home') }}">Dashboard</a>
{% if g.user.role=='volunteer' %}<a href="{{ url_for('jobs') }}">Find jobs</a>{% endif %}
<a href="{{ url_for('logout') }}">Log out</a>
{% else %}<a href="{{ url_for('login') }}">Log in</a><a class="cta" href="{{ url_for('register') }}">Sign up</a>{% endif %}
</div></nav><main>
{% for cat,msg in get_flashed_messages(with_categories=true) %}<div class="flash {{cat}}">{{msg}}</div>{% endfor %}
{% if g.user and g.user.verified==0 %}<div class="flash err">&#9203; Your ID is waiting for verification. You can't post or accept jobs until then.</div>{% endif %}{% if g.user and g.user.verified==-1 %}<div class="flash err">&#10060; Your ID was not approved. Sign up again with a clearer photo of your ID.</div>{% endif %}
{% block body %}{% endblock %}</main>
<script>
var bg=document.getElementById('bg'),lk=document.getElementById('lk');
bg.onclick=function(){bg.classList.toggle('open');lk.classList.toggle('open')};
document.querySelectorAll('.card').forEach(function(c,i){c.style.animationDelay=(i*80)+'ms'});
setTimeout(function(){document.querySelectorAll('.flash').forEach(function(f){f.style.opacity=0;f.style.transform='translateY(-10px)';setTimeout(function(){f.remove()},700)})},5000);
</script></body></html>"""

T["login.html"] = """{% extends 'base.html' %}{% block body %}<div class="hero"><h1>Welcome back</h1><p>Neighbors helping neighbors.</p></div><div class="card"><h2>Log in</h2>
<form method="post"><label>Email</label><input name="email" type="email" required>
<label>Password</label><input name="password" type="password" required>
<button>Log in</button></form></div>{% endblock %}"""

T["register.html"] = """{% extends 'base.html' %}{% block body %}<div class="hero"><h1>Join Porchlight</h1><p>Ask for a hand, or give one.</p></div><div class="card"><h2>Create account</h2>
<form method="post" enctype="multipart/form-data">
<label>I am a...</label><select name="role"><option value="senior">Senior who needs help</option><option value="volunteer">Volunteer</option></select>
<label>Full name</label><input name="name" required>
<label>Age</label><input name="age" type="number" min="1" max="120" required>
<label>Town</label><input name="town" required>
<label>Email</label><input name="email" type="email" required>
<label>Password</label><input name="password" type="password" required>
<label>Photo of government ID</label><input name="id_photo" type="file" accept="image/*,.pdf" required>
<small>Only our admin sees this, to verify you're real.</small><br>
<button>Sign up</button></form></div>{% endblock %}"""

T["senior.html"] = """{% extends 'base.html' %}{% block body %}
{% if g.user.verified==1 %}<div class="card"><h2>Ask for help</h2>
<form method="post" action="{{ url_for('new_request') }}">
<label>Town</label><input name="town" value="{{ g.user.town }}" required>
<label>Address (only shared with your matched volunteer)</label><input name="address" required>
<label>What do you need help with?</label><textarea name="description" rows="3" required placeholder="e.g. Grocery shopping, yard work, setting up my phone"></textarea>
<label>Earliest you can be helped</label><input type="datetime-local" name="start" required>
<label>Latest you can be helped until</label><input type="datetime-local" name="end" required>
<button>Find me a volunteer</button></form></div>{% endif %}
<h2>My requests</h2>
{% for r in reqs %}<div class="card"><span class="tag {{r.status}}">{{r.status}}</span>
<p><b>{{ r.description }}</b></p><p class="muted">{{ r.town }} &middot; window: {{ r.start|fmt }} &ndash; {{ r.end|fmt }}</p>
{% if r.status=='open' %}<p>&#128269; Looking for a volunteer...</p>{% endif %}
{% if r.volunteer_id %}{% set a = avg_rating(r.volunteer_id) %}
<p>&#9989; <b>{{ r.vname }}</b>{% if a[0] %} (&#9733; {{ a[0] }}, {{ a[1] }} reviews){% endif %} will arrive on <b>{{ r.sched_start|fmt }}</b> (available until {{ r.sched_end|fmt }}).</p>{% endif %}
{% if r.status in ('open','matched') %}<form class="inline" method="post" action="{{ url_for('cancel_request', rid=r.id) }}"><button class="red">Cancel</button></form>{% endif %}
{% if r.status=='completed' and r.id not in reviewed %}<a class="btn green" href="{{ url_for('review', rid=r.id) }}">Review volunteer</a>{% endif %}
</div>{% else %}<p class="muted">Nothing yet.</p>{% endfor %}{% endblock %}"""

T["volunteer.html"] = """{% extends 'base.html' %}{% block body %}
{% if g.user.verified==1 %}<div class="card"><h2>When are you available?</h2>
<form method="post" action="{{ url_for('add_availability') }}">
<label>Town</label><input name="town" value="{{ g.user.town }}" required>
<label>From</label><input type="datetime-local" name="start" required>
<label>Until</label><input type="datetime-local" name="end" required>
<button>Add availability</button> <a class="btn grey" href="{{ url_for('jobs') }}">Show jobs</a></form>
{% for a in av %}<p>&#128197; {{ a.town }}: {{ a.start|fmt }} &ndash; {{ a.end|fmt }}
<form class="inline" method="post" action="{{ url_for('del_availability', aid=a.id) }}"><button class="red">x</button></form></p>{% endfor %}</div>{% endif %}
<h2>My jobs</h2>
{% for j in jobs %}<div class="card"><span class="tag {{j.status}}">{{j.status}}</span>
<p><b>{{ j.description }}</b></p>
{% if j.status in ('matched','completed') %}
<p>&#128205; <b>{{ j.address }}, {{ j.town }}</b><br>&#128339; Be there: <b>{{ j.sched_start|fmt }}</b> (until {{ j.sched_end|fmt }})<br>Senior: {{ j.sname }}</p>{% endif %}
{% if j.status=='matched' %}<form method="post" action="{{ url_for('complete', rid=j.id) }}"><button class="green">Mark complete</button></form>{% endif %}
{% if j.status=='completed' and j.id not in reviewed %}<a class="btn green" href="{{ url_for('review', rid=j.id) }}">Review senior</a>{% endif %}
</div>{% else %}<p class="muted">No jobs yet.</p>{% endfor %}{% endblock %}"""

T["jobs.html"] = """{% extends 'base.html' %}{% block body %}<h2>Jobs in {{ town }}</h2>
<form method="get"><label>Town</label><input name="town" value="{{ town }}"><button>Search</button></form>
{% if not has_avail %}<div class="flash err">Add your availability for {{ town }} first and we'll show jobs that fit your schedule.</div>{% endif %}
{% for r,o in matches %}{% set a = avg_rating(r.senior_id) %}<div class="card">
<p><b>{{ r.description }}</b></p>
<p class="muted">Senior: {{ r.sname }}{% if a[0] %} (&#9733; {{ a[0] }}, {{ a[1] }} reviews){% endif %}<br>
Needs help: {{ r.start|fmt }} &ndash; {{ r.end|fmt }}</p>
<p>&#9989; You'd arrive: <b>{{ o[0]|fmt }}</b> (you're both free until {{ o[1]|fmt }})</p>
<form method="post" action="{{ url_for('accept', rid=r.id) }}"><button>Accept this job</button></form></div>
{% else %}{% if has_avail %}<p class="muted">No open jobs match your times right now.</p>{% endif %}{% endfor %}{% endblock %}"""

T["review.html"] = """{% extends 'base.html' %}{% block body %}<div class="card"><h2>Review {{ other.name }}</h2>
<form method="post"><label>Rating</label><select name="rating">
<option value="5">5 - Great</option><option value="4">4</option><option value="3">3</option><option value="2">2</option><option value="1">1 - Bad</option></select>
<label>Comment</label><textarea name="comment" rows="3"></textarea><button>Submit</button></form></div>{% endblock %}"""

T["admin_login.html"] = """{% extends 'base.html' %}{% block body %}<div class="card"><h2>Admin</h2>
<form method="post"><label>Password</label><input type="password" name="password"><button>Enter</button></form></div>{% endblock %}"""

T["admin.html"] = """{% extends 'base.html' %}{% block body %}
<h2>&#128273; ID verification <a class="btn grey" style="font-size:.6em;padding:6px 12px" href="{{ url_for('admin_logout') }}">Admin log out</a></h2>
{% macro person(u) %}<b>{{ u.name }}</b> ({{ u.role }}, age {{ u.age }}, {{ u.town }})<br><span class="muted">{{ u.email }}</span><br>
<a href="{{ url_for('admin_id', fname=u.id_file) }}" target="_blank">&#128247; View ID</a><br>{% endmacro %}
{% macro act(u, action, label, cls) %}<form class="inline" method="post" action="{{ url_for('admin_set', uid=u.id, action=action) }}"><button class="{{cls}}">{{label}}</button></form> {% endmacro %}

<h2>&#9203; Pending ({{ pending|length }})</h2>
{% for u in pending %}<div class="card">{{ person(u) }}{{ act(u,'approve','Approve','green') }}{{ act(u,'reject','Reject','red') }}</div>
{% else %}<p class="muted">Nobody waiting.</p>{% endfor %}

<h2>&#9989; Verified ({{ approved|length }})</h2>
{% for u in approved %}<div class="card">{{ person(u) }}{{ act(u,'reject','Revoke','red') }}</div>
{% else %}<p class="muted">Nobody yet.</p>{% endfor %}

<h2>&#10060; Rejected ({{ rejected|length }})</h2>
{% for u in rejected %}<div class="card">{{ person(u) }}{{ act(u,'approve','Approve instead','green') }}{{ act(u,'delete','Delete account','grey') }}</div>
{% else %}<p class="muted">Nobody here.</p>{% endfor %}
{% endblock %}"""

app.jinja_env.loader = DictLoader(T)

init_db()

if __name__ == "__main__":
    app.run(debug=True)