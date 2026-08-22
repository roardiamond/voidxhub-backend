import os
import re
import json
import sqlite3
import time
import secrets
import urllib.request
import urllib.parse
import datetime
import jwt
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# ---------------- Config ----------------
SECRET_KEY = os.environ.get("VOIDXHUB_SECRET", os.environ.get("SECRET_KEY", "voidxhub-dev-secret-change-in-production"))
IS_PRODUCTION = os.environ.get("VOIDXHUB_ENV") == "production"

if IS_PRODUCTION and SECRET_KEY in ("voidxhub-dev-secret-change-in-production", ""):
    raise SystemExit("FATAL: Set a real VOIDXHUB_SECRET in production")

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin").lower()
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "voidxhub.db")
TOKEN_EXP_HOURS = 24 * 7

ALLOWED_ORIGINS = {
    "capacitor://localhost",
    "http://localhost",
    "https://localhost",
    "ionic://localhost",
    "https://voidxhub.in",
    "https://www.voidxhub.in",
} | {o.strip() for o in os.environ.get("VOIDXHUB_ALLOWED_ORIGINS", "").split(",") if o.strip()}

CORS(app, supports_credentials=True, origins=list(ALLOWED_ORIGINS))

app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

# ---------------- Helpers ----------------
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,20}$")
MODE_PLAYER_COUNTS = {"solo": 1, "duo": 2, "trio": 3, "squad": 4, "4v4": 4, "5v5": 5, "6v6": 6}

_rate_buckets = {}

def rate_limited(key, max_attempts, window_seconds):
    now = time.time()
    bucket = _rate_buckets.setdefault(key, [])
    bucket[:] = [t for t in bucket if now - t < window_seconds]
    if len(bucket) >= max_attempts:
        return True
    bucket.append(now)
    return False

def client_ip():
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def send_telegram(text):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        data = urllib.parse.urlencode({
            "chat_id": TELEGRAM_CHAT_ID,
            "text": text,
            "parse_mode": "HTML"
        }).encode()
        req = urllib.request.Request(url, data=data)
        urllib.request.urlopen(req, timeout=10)
        return True
    except Exception as e:
        print("[TG ERROR]", e)
        return False

def log_event(event, user_id=None, username=None, detail=""):
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO audit_log (event, user_id, username, ip_address, detail) VALUES (?, ?, ?, ?, ?)",
            (event, user_id, username, client_ip(), detail),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

def row_to_dict(row):
    return dict(row) if row else None

def slots_filled_count(conn, tournament_id):
    cur = conn.execute(
        "SELECT COUNT(*) c FROM registrations WHERE tournament_id=? AND payment_status != 'rejected'",
        (tournament_id,),
    )
    return cur.fetchone()["c"]

# ---------------- Auth (JWT) ----------------
def issue_token(user_row):
    payload = {
        "user_id": user_row["id"],
        "username": user_row["username"],
        "role": user_row["role"],
        "tv": user_row["token_version"] if "token_version" in user_row.keys() else 0,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_EXP_HOURS),
        "iat": datetime.datetime.utcnow(),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def decode_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def get_token_from_request():
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header[7:]
    return None

def _token_version_matches(payload):
    conn = get_db()
    row = conn.execute("SELECT token_version FROM users WHERE id=?", (payload.get("user_id"),)).fetchone()
    conn.close()
    if row is None:
        return False
    return row["token_version"] == payload.get("tv", 0)

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = get_token_from_request()
        if not token:
            return jsonify({"error": "Login required"}), 401
        payload = decode_token(token)
        if not payload or not _token_version_matches(payload):
            return jsonify({"error": "Session expired, please log in again"}), 401
        request.user = payload
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = get_token_from_request()
        if not token:
            return jsonify({"error": "Login required"}), 401
        payload = decode_token(token)
        if not payload or not _token_version_matches(payload):
            return jsonify({"error": "Session expired, please log in again"}), 401
        if payload.get("role") != "admin":
            return jsonify({"error": "Admin access only"}), 403
        request.user = payload
        return f(*args, **kwargs)
    return wrapper

# ---------------- Database ----------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE,
    phone TEXT,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    token_version INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_login TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event TEXT NOT NULL,
    user_id INTEGER,
    username TEXT,
    ip_address TEXT,
    detail TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS games (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    slug TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS tournaments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    game_id INTEGER NOT NULL REFERENCES games(id),
    mode TEXT NOT NULL DEFAULT 'squad',
    description TEXT,
    entry_fee INTEGER NOT NULL DEFAULT 0,
    prize_pool INTEGER NOT NULL DEFAULT 0,
    slots_total INTEGER NOT NULL DEFAULT 25,
    match_date TEXT,
    status TEXT NOT NULL DEFAULT 'upcoming',
    room_id TEXT,
    room_pass TEXT,
    upi_id TEXT,
    created_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS registrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tournament_id INTEGER NOT NULL REFERENCES tournaments(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    team_name TEXT NOT NULL,
    players TEXT,
    payment_status TEXT NOT NULL DEFAULT 'pending',
    utr_number TEXT,
    slot_number INTEGER,
    registered_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(tournament_id, user_id)
);

CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tournament_id INTEGER NOT NULL REFERENCES tournaments(id),
    team_name TEXT NOT NULL,
    position INTEGER NOT NULL,
    kills INTEGER DEFAULT 0,
    prize_amount INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS product_orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_code TEXT UNIQUE NOT NULL,
    user_id INTEGER,
    username TEXT,
    telegram TEXT,
    tool TEXT,
    plan_type TEXT,
    brand TEXT,
    price_inr INTEGER,
    utr_number TEXT,
    status TEXT DEFAULT 'pending',
    download_link TEXT,
    admin_note TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
"""

SEED_GAMES = [
    "BGMI", "Free Fire", "Valorant", "Counter-Strike 2",
    "Call of Duty Mobile", "PUBG PC", "Apex Legends", "Fortnite", "Clash Squad",
]

def init_db():
    conn = get_db()
    conn.executescript(SCHEMA)

    # Migrations for older DBs
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
    if "token_version" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0")
    if "failed_attempts" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0")
    if "locked_until" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN locked_until TEXT")
    if "email" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
    if "phone" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN phone TEXT")
    if "role" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
    if "last_login" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN last_login TEXT")

    # product_orders migration
    pcols = {row["name"] for row in conn.execute("PRAGMA table_info(product_orders)")}
    if "utr_number" not in pcols:
        try:
            conn.execute("ALTER TABLE product_orders ADD COLUMN utr_number TEXT")
        except Exception:
            pass

    for name in SEED_GAMES:
        slug = name.lower().replace(" ", "-")
        conn.execute("INSERT OR IGNORE INTO games (name, slug) VALUES (?, ?)", (name, slug))

    # Ensure admin exists
    admin = conn.execute("SELECT id FROM users WHERE username = ?", (ADMIN_USERNAME,)).fetchone()
    if not admin:
        conn.execute(
            "INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?, ?, ?, 'admin', ?)",
            (ADMIN_USERNAME, f"{ADMIN_USERNAME}@voidxhub.in",
             generate_password_hash(ADMIN_PASSWORD),
             datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
    else:
        # Make sure existing admin has role=admin
        conn.execute("UPDATE users SET role='admin' WHERE username=?", (ADMIN_USERNAME,))

    conn.commit()
    conn.close()
    print("[VOIDXHUB] Database ready – Tournament + Orders mode")

# ---------------- CORS preflight ----------------
@app.route("/api/<path:_any>", methods=["OPTIONS"])
def cors_preflight(_any):
    return ("", 204)

@app.after_request
def add_security_headers(response):
    origin = request.headers.get("Origin")
    if origin and origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, DELETE, OPTIONS"
        response.headers["Vary"] = "Origin"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if IS_PRODUCTION:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response

# ==================== AUTH ====================

@app.route("/api/auth/register", methods=["POST"])
def register():
    if rate_limited(f"register:{client_ip()}", 5, 3600):
        return jsonify({"error": "Too many signups. Try again later."}), 429

    data = request.get_json(force=True, silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    email = (data.get("email") or "").strip().lower()
    phone = (data.get("phone") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    if not USERNAME_RE.match(username):
        return jsonify({"error": "Username must be 3-20 characters: letters, numbers, underscores only"}), 400
    if email and not EMAIL_RE.match(email):
        return jsonify({"error": "Enter a valid email address"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    conn = get_db()
    try:
        pw_hash = generate_password_hash(password)
        cur = conn.execute(
            "INSERT INTO users (username, email, phone, password_hash) VALUES (?, ?, ?, ?)",
            (username, email or None, phone or None, pw_hash),
        )
        conn.commit()
        user = conn.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
        token = issue_token(user)
        log_event("register", user_id=user["id"], username=user["username"])
        return jsonify({
            "success": True,
            "token": token,
            "user": {"id": user["id"], "username": user["username"], "email": user["email"], "role": user["role"]}
        }), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or email already taken"}), 409
    finally:
        conn.close()

@app.route("/api/auth/login", methods=["POST"])
def login():
    if rate_limited(f"login:{client_ip()}", 10, 300):
        return jsonify({"error": "Too many login attempts. Try again later."}), 429

    data = request.get_json(force=True, silent=True) or {}
    identifier = (data.get("username") or data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE lower(username)=? OR lower(email)=?", (identifier, identifier)
    ).fetchone()

    if user and user["locked_until"]:
        try:
            locked_until = datetime.datetime.fromisoformat(user["locked_until"])
            if datetime.datetime.utcnow() < locked_until:
                conn.close()
                return jsonify({"error": "Account temporarily locked. Try again later."}), 423
        except Exception:
            pass

    if not user or not check_password_hash(user["password_hash"], password):
        if user:
            attempts = (user["failed_attempts"] or 0) + 1
            locked_until = None
            if attempts >= 5:
                locked_until = (datetime.datetime.utcnow() + datetime.timedelta(minutes=15)).isoformat()
            conn.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                         (attempts, locked_until, user["id"]))
            conn.commit()
        conn.close()
        return jsonify({"error": "Invalid username/email or password"}), 401

    conn.execute("UPDATE users SET failed_attempts=0, locked_until=NULL, last_login=? WHERE id=?",
                 (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user["id"]))
    conn.commit()
    conn.close()

    token = issue_token(user)
    log_event("login", user_id=user["id"], username=user["username"])
    return jsonify({
        "success": True,
        "token": token,
        "user": {"id": user["id"], "username": user["username"], "email": user["email"], "role": user["role"]}
    })

@app.route("/api/auth/me", methods=["GET"])
@login_required
def me():
    conn = get_db()
    user = conn.execute("SELECT id, username, email, phone, role, created_at FROM users WHERE id=?",
                        (request.user["user_id"],)).fetchone()
    conn.close()
    return jsonify({"success": True, "user": row_to_dict(user)})

@app.route("/api/auth/change-password", methods=["POST"])
@login_required
def change_password():
    data = request.get_json(force=True, silent=True) or {}
    current = data.get("current_password") or ""
    new = data.get("new_password") or ""
    if len(new) < 6:
        return jsonify({"error": "New password must be at least 6 characters"}), 400

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (request.user["user_id"],)).fetchone()
    if not user or not check_password_hash(user["password_hash"], current):
        conn.close()
        return jsonify({"error": "Current password is incorrect"}), 401

    conn.execute("UPDATE users SET password_hash=?, token_version = token_version + 1 WHERE id=?",
                 (generate_password_hash(new), user["id"]))
    conn.commit()
    fresh = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
    conn.close()
    new_token = issue_token(fresh)
    return jsonify({"success": True, "message": "Password changed", "token": new_token})

# ==================== PRODUCT ORDERS ====================

@app.route("/api/orders/create", methods=["POST"])
def create_product_order():
    data = request.get_json(force=True, silent=True) or {}
    tool = (data.get("tool") or "unknown").strip()
    plan_type = (data.get("type") or data.get("plan_type") or "public").strip()
    brand = (data.get("brand") or "unknown").strip()
    price_inr = int(data.get("price") or data.get("price_inr") or 0)
    telegram = (data.get("telegram") or "").strip()
    utr_number = (data.get("utr_number") or data.get("utr") or "").strip()[:40]
    username = (data.get("username") or "").strip().lower()

    user_id = None
    token = get_token_from_request()
    if token:
        payload = decode_token(token)
        if payload and _token_version_matches(payload):
            user_id = payload["user_id"]
            if not username:
                username = payload.get("username", "")

    if not telegram:
        return jsonify({"success": False, "error": "Telegram username required"}), 400
    if not username:
        username = "guest"

    order_code = "VxH-" + secrets.token_hex(4).upper()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    conn.execute("""INSERT INTO product_orders
        (order_code, user_id, username, telegram, tool, plan_type, brand, price_inr, utr_number, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)""",
        (order_code, user_id, username, telegram, tool, plan_type, brand, price_inr, utr_number or None, now))
    conn.commit()
    conn.close()

    tg_msg = (
        f"🛒 <b>NEW ORDER - VOIDXHUB</b>\n\n"
        f"Order: <code>{order_code}</code>\n"
        f"User: {username}\n"
        f"Telegram: @{telegram.lstrip('@')}\n"
        f"Tool: {tool}\n"
        f"Plan: {plan_type.upper()}\n"
        f"Brand: {brand.upper()}\n"
        f"Price: ₹{price_inr}\n"
        f"UTR: {utr_number or 'not provided yet'}\n"
        f"Time: {now}\n\n"
        f"Verify payment → upload download link in Admin."
    )
    send_telegram(tg_msg)

    return jsonify({
        "success": True,
        "order_code": order_code,
        "message": "Order placed. Pay via UPI, enter UTR if not already, then wait for admin to verify and deliver."
    })

@app.route("/api/orders/my", methods=["GET"])
def my_orders():
    user_id = None
    username = request.args.get("username")
    token = get_token_from_request()
    if token:
        payload = decode_token(token)
        if payload and _token_version_matches(payload):
            user_id = payload["user_id"]
            username = payload.get("username")

    conn = get_db()
    if user_id:
        rows = conn.execute("SELECT * FROM product_orders WHERE user_id = ? ORDER BY id DESC", (user_id,)).fetchall()
    elif username:
        rows = conn.execute("SELECT * FROM product_orders WHERE username = ? ORDER BY id DESC", (username.lower(),)).fetchall()
    else:
        conn.close()
        return jsonify({"success": False, "error": "Login or username required"}), 401
    conn.close()
    return jsonify({"success": True, "orders": [dict(r) for r in rows]})

@app.route("/api/orders/lookup", methods=["POST"])
def lookup_order():
    data = request.get_json(force=True, silent=True) or {}
    code = (data.get("order_code") or "").strip().upper()
    telegram = (data.get("telegram") or "").strip().lstrip("@").lower()
    if not code:
        return jsonify({"success": False, "error": "Order code required"}), 400
    conn = get_db()
    row = conn.execute("SELECT * FROM product_orders WHERE order_code = ?", (code,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"success": False, "error": "Order not found"}), 404
    if telegram and row["telegram"].lstrip("@").lower() != telegram:
        return jsonify({"success": False, "error": "Telegram does not match"}), 403
    return jsonify({"success": True, "order": dict(row)})

@app.route("/api/admin/orders", methods=["GET"])
@admin_required
def admin_orders():
    conn = get_db()
    rows = conn.execute("SELECT * FROM product_orders ORDER BY id DESC LIMIT 150").fetchall()
    conn.close()
    return jsonify({"success": True, "orders": [dict(r) for r in rows]})

@app.route("/api/admin/orders/fulfill", methods=["POST"])
@admin_required
def fulfill_order():
    data = request.get_json(force=True, silent=True) or {}
    order_code = (data.get("order_code") or "").strip().upper()
    download_link = (data.get("download_link") or "").strip()
    admin_note = (data.get("admin_note") or "").strip()
    if not order_code or not download_link:
        return jsonify({"success": False, "error": "order_code and download_link required"}), 400

    conn = get_db()
    row = conn.execute("SELECT * FROM product_orders WHERE order_code = ?", (order_code,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "error": "Order not found"}), 404

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "UPDATE product_orders SET status = 'delivered', download_link = ?, admin_note = ?, updated_at = ? WHERE order_code = ?",
        (download_link, admin_note, now, order_code)
    )
    conn.commit()
    conn.close()

    send_telegram(
        f"✅ <b>ORDER DELIVERED</b>\n\n"
        f"Order: <code>{order_code}</code>\n"
        f"User: @{row['telegram'].lstrip('@')}\n"
        f"Tool: {row['tool']} / {row['plan_type']}\n"
        f"Link set. User can download from My Orders."
    )
    return jsonify({"success": True, "message": "Order fulfilled. User can download from My Orders."})

# ==================== GAMES & TOURNAMENTS ====================

@app.route("/api/games", methods=["GET"])
def list_games():
    conn = get_db()
    games = conn.execute("SELECT * FROM games ORDER BY name").fetchall()
    conn.close()
    return jsonify([dict(g) for g in games])

@app.route("/api/tournaments", methods=["GET"])
def list_tournaments():
    game_slug = request.args.get("game")
    status = request.args.get("status")

    conn = get_db()
    query = """
        SELECT t.*, g.name as game_name, g.slug as game_slug
        FROM tournaments t JOIN games g ON t.game_id = g.id
        WHERE 1=1
    """
    params = []
    if game_slug:
        query += " AND g.slug = ?"
        params.append(game_slug)
    if status:
        query += " AND t.status = ?"
        params.append(status)
    query += " ORDER BY t.match_date ASC"

    rows = conn.execute(query, params).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["slots_filled"] = slots_filled_count(conn, r["id"])
        d.pop("room_id", None)
        d.pop("room_pass", None)
        d.pop("upi_id", None)
        result.append(d)
    conn.close()
    return jsonify(result)

@app.route("/api/tournaments/<int:tid>", methods=["GET"])
def get_tournament(tid):
    conn = get_db()
    row = conn.execute(
        """SELECT t.*, g.name as game_name, g.slug as game_slug
           FROM tournaments t JOIN games g ON t.game_id = g.id WHERE t.id=?""",
        (tid,),
    ).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Tournament not found"}), 404

    d = dict(row)
    d["slots_filled"] = slots_filled_count(conn, tid)

    reveal = False
    token_user = None
    token = get_token_from_request()
    if token:
        payload = decode_token(token)
        if payload and _token_version_matches(payload):
            token_user = payload
            if payload.get("role") == "admin":
                reveal = True
            else:
                reg = conn.execute(
                    "SELECT * FROM registrations WHERE tournament_id=? AND user_id=? AND payment_status='verified'",
                    (tid, payload["user_id"]),
                ).fetchone()
                if reg:
                    reveal = True

    if not reveal:
        d.pop("room_id", None)
        d.pop("room_pass", None)

    results = conn.execute("SELECT * FROM results WHERE tournament_id=? ORDER BY position ASC", (tid,)).fetchall()
    d["results"] = [dict(x) for x in results]

    my_registration = None
    if token_user:
        reg = conn.execute(
            "SELECT * FROM registrations WHERE tournament_id=? AND user_id=?",
            (tid, token_user["user_id"]),
        ).fetchone()
        if reg:
            my_registration = dict(reg)

    conn.close()
    d["my_registration"] = my_registration
    return jsonify(d)

@app.route("/api/tournaments/<int:tid>/register", methods=["POST"])
@login_required
def register_for_tournament(tid):
    if rate_limited(f"reg:{request.user['user_id']}", 10, 600):
        return jsonify({"error": "Too many registration attempts. Slow down."}), 429

    data = request.get_json(force=True, silent=True) or {}
    team_name = (data.get("team_name") or "").strip()[:60]
    utr_number = (data.get("utr_number") or "").strip()[:40]

    raw_players = data.get("players") or []
    players = []
    for p in raw_players[:10]:
        if isinstance(p, dict):
            ign = str(p.get("ign", "")).strip()[:40]
            uid = str(p.get("uid", "")).strip()[:20]
        else:
            ign, uid = str(p).strip()[:40], ""
        if ign or uid:
            players.append({"ign": ign, "uid": uid})

    if not team_name:
        return jsonify({"error": "Team name is required"}), 400

    conn = get_db()
    tournament = conn.execute("SELECT * FROM tournaments WHERE id=?", (tid,)).fetchone()
    if not tournament:
        conn.close()
        return jsonify({"error": "Tournament not found"}), 404

    required_count = MODE_PLAYER_COUNTS.get(tournament["mode"], max(len(players), 1))
    if len(players) < required_count:
        conn.close()
        return jsonify({"error": f"This is a {tournament['mode']} tournament — {required_count} player(s) with IGN + UID required"}), 400
    if any(not p["ign"] or not p["uid"] for p in players[:required_count]):
        conn.close()
        return jsonify({"error": "Every player needs both an in-game name and a UID"}), 400
    if not all(p["uid"].isdigit() for p in players if p["uid"]):
        conn.close()
        return jsonify({"error": "UID must be numeric"}), 400

    if tournament["status"] != "upcoming":
        conn.close()
        return jsonify({"error": "Registration is closed for this tournament"}), 400

    filled = slots_filled_count(conn, tid)
    if filled >= tournament["slots_total"]:
        conn.close()
        return jsonify({"error": "All slots are full"}), 400

    if tournament["entry_fee"] > 0 and not utr_number:
        conn.close()
        return jsonify({"error": "UTR / transaction ID is required for paid tournaments"}), 400

    payment_status = "pending" if tournament["entry_fee"] > 0 else "verified"

    try:
        conn.execute(
            """INSERT INTO registrations (tournament_id, user_id, team_name, players, payment_status, utr_number, slot_number)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (tid, request.user["user_id"], team_name, json.dumps(players), payment_status, utr_number, filled + 1),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "You are already registered for this tournament"}), 409
    conn.close()
    return jsonify({"message": "Registered successfully", "payment_status": payment_status}), 201

@app.route("/api/registrations/me", methods=["GET"])
@login_required
def my_registrations():
    conn = get_db()
    rows = conn.execute(
        """SELECT r.*, t.title, t.match_date, t.status as tournament_status, t.entry_fee,
                  t.room_id, t.room_pass, g.name as game_name
           FROM registrations r
           JOIN tournaments t ON r.tournament_id = t.id
           JOIN games g ON t.game_id = g.id
           WHERE r.user_id=?
           ORDER BY r.registered_at DESC""",
        (request.user["user_id"],),
    ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        if d["payment_status"] != "verified":
            d.pop("room_id", None)
            d.pop("room_pass", None)
        result.append(d)
    conn.close()
    return jsonify(result)

@app.route("/api/leaderboard", methods=["GET"])
def leaderboard():
    game_slug = request.args.get("game")
    conn = get_db()
    query = """
        SELECT r.team_name,
               COUNT(DISTINCT r.tournament_id) as events,
               SUM(r.prize_amount) as total_prize,
               SUM(r.kills) as total_kills,
               SUM(CASE WHEN r.position = 1 THEN 1 ELSE 0 END) as wins
        FROM results r
        JOIN tournaments t ON r.tournament_id = t.id
        JOIN games g ON t.game_id = g.id
        WHERE 1=1
    """
    params = []
    if game_slug:
        query += " AND g.slug = ?"
        params.append(game_slug)
    query += " GROUP BY r.team_name ORDER BY total_prize DESC, wins DESC LIMIT 50"

    rows = conn.execute(query, params).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ==================== ADMIN TOURNAMENTS ====================

@app.route("/api/admin/tournaments", methods=["POST"])
@admin_required
def admin_create_tournament():
    data = request.get_json(force=True, silent=True) or {}
    required = ["title", "game_id", "match_date"]
    for field in required:
        if not data.get(field):
            return jsonify({"error": f"{field} is required"}), 400

    conn = get_db()
    cur = conn.execute(
        """INSERT INTO tournaments (title, game_id, mode, description, entry_fee, prize_pool,
                                     slots_total, match_date, upi_id, created_by)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            data["title"], data["game_id"], data.get("mode", "squad"), data.get("description", ""),
            int(data.get("entry_fee", 0)), int(data.get("prize_pool", 0)),
            int(data.get("slots_total", 25)), data["match_date"], data.get("upi_id", ""),
            request.user["user_id"],
        ),
    )
    conn.commit()
    tid = cur.lastrowid
    conn.close()
    return jsonify({"message": "Tournament created", "id": tid}), 201

@app.route("/api/admin/tournaments/<int:tid>", methods=["PATCH"])
@admin_required
def admin_update_tournament(tid):
    data = request.get_json(force=True, silent=True) or {}
    allowed = ["title", "description", "entry_fee", "prize_pool", "slots_total",
               "match_date", "status", "room_id", "room_pass", "upi_id", "mode"]
    updates = {k: v for k, v in data.items() if k in allowed}
    if not updates:
        return jsonify({"error": "No valid fields to update"}), 400

    conn = get_db()
    exists = conn.execute("SELECT id FROM tournaments WHERE id=?", (tid,)).fetchone()
    if not exists:
        conn.close()
        return jsonify({"error": "Tournament not found"}), 404

    set_clause = ", ".join(f"{k}=?" for k in updates)
    conn.execute(f"UPDATE tournaments SET {set_clause} WHERE id=?", (*updates.values(), tid))
    conn.commit()
    conn.close()
    log_event("admin_update_tournament", user_id=request.user["user_id"], username=request.user["username"], detail=f"tournament_id={tid}")
    return jsonify({"message": "Tournament updated"})

@app.route("/api/admin/tournaments/<int:tid>", methods=["DELETE"])
@admin_required
def admin_delete_tournament(tid):
    conn = get_db()
    conn.execute("DELETE FROM registrations WHERE tournament_id=?", (tid,))
    conn.execute("DELETE FROM results WHERE tournament_id=?", (tid,))
    conn.execute("DELETE FROM tournaments WHERE id=?", (tid,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Tournament deleted"})

@app.route("/api/admin/tournaments/<int:tid>/registrations", methods=["GET"])
@admin_required
def admin_list_registrations(tid):
    conn = get_db()
    rows = conn.execute(
        """SELECT r.*, u.username, u.email, u.phone
           FROM registrations r JOIN users u ON r.user_id = u.id
           WHERE r.tournament_id=? ORDER BY r.registered_at ASC""",
        (tid,),
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/admin/registrations/<int:rid>/payment", methods=["PATCH"])
@admin_required
def admin_update_payment(rid):
    data = request.get_json(force=True, silent=True) or {}
    status = data.get("status")
    if status not in ("verified", "rejected", "pending"):
        return jsonify({"error": "Invalid status"}), 400

    conn = get_db()
    conn.execute("UPDATE registrations SET payment_status=? WHERE id=?", (status, rid))
    conn.commit()
    conn.close()
    log_event("admin_payment_update", user_id=request.user["user_id"], username=request.user["username"], detail=f"registration_id={rid} status={status}")
    return jsonify({"message": f"Payment marked as {status}"})

@app.route("/api/admin/tournaments/<int:tid>/results", methods=["POST"])
@admin_required
def admin_add_results(tid):
    data = request.get_json(force=True, silent=True) or {}
    results = data.get("results") or []

    conn = get_db()
    conn.execute("DELETE FROM results WHERE tournament_id=?", (tid,))
    for r in results:
        conn.execute(
            "INSERT INTO results (tournament_id, team_name, position, kills, prize_amount) VALUES (?, ?, ?, ?, ?)",
            (tid, str(r.get("team_name", ""))[:60], int(r.get("position", 0)), int(r.get("kills", 0)), int(r.get("prize_amount", 0))),
        )
    conn.execute("UPDATE tournaments SET status='completed' WHERE id=?", (tid,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Results published"})

@app.route("/api/admin/stats", methods=["GET"])
@admin_required
def admin_stats():
    conn = get_db()
    total_tournaments = conn.execute("SELECT COUNT(*) c FROM tournaments").fetchone()["c"]
    total_users = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    pending_payments = conn.execute("SELECT COUNT(*) c FROM registrations WHERE payment_status='pending'").fetchone()["c"]
    pending_orders = conn.execute("SELECT COUNT(*) c FROM product_orders WHERE status='pending'").fetchone()["c"]
    revenue = conn.execute(
        """SELECT COALESCE(SUM(t.entry_fee), 0) rev FROM registrations r
           JOIN tournaments t ON r.tournament_id = t.id WHERE r.payment_status='verified'"""
    ).fetchone()["rev"]
    conn.close()
    return jsonify({
        "total_tournaments": total_tournaments,
        "total_users": total_users,
        "pending_payments": pending_payments,
        "pending_orders": pending_orders,
        "revenue": revenue,
    })

@app.route("/api/admin/users", methods=["GET"])
@admin_required
def admin_users():
    conn = get_db()
    users = conn.execute("SELECT id, username, email, role, created_at, last_login FROM users ORDER BY id DESC").fetchall()
    conn.close()
    return jsonify({"success": True, "users": [dict(u) for u in users]})

@app.route("/api/admin/audit-log", methods=["GET"])
@admin_required
def admin_audit_log():
    conn = get_db()
    rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ==================== HEALTH ====================

@app.route("/")
def home():
    return jsonify({
        "status": "online",
        "service": "VOIDXHUB Unified Backend",
        "version": "2.0",
        "features": ["auth", "tournaments", "product-orders", "leaderboard"]
    })

# ---------------- Boot ----------------
init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
