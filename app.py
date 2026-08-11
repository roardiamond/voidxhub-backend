from flask import Flask, request, jsonify, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import secrets
from datetime import datetime
from functools import wraps
import hmac
import hashlib

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
CORS(app, supports_credentials=True, origins=["*"])

# ==================== CONFIG ====================
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

# Razorpay Test Mode Keys (env se lo)
RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID", "rzp_test_xxxxx")
RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET", "your_test_secret")

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "voidxhub.db")

# Credit Packages (Rupees → Credits)
CREDIT_PACKAGES = {
    "pack_100":  {"credits": 100,  "amount": 4900,  "label": "100 Credits - ₹49"},
    "pack_300":  {"credits": 300,  "amount": 12900, "label": "300 Credits - ₹129"},
    "pack_700":  {"credits": 700,  "amount": 24900, "label": "700 Credits - ₹249"},
    "pack_1500": {"credits": 1500, "amount": 49900, "label": "1500 Credits - ₹499"},
}

# Feature costs (credits)
FEATURE_COSTS = {
    "esp": 50,
    "headshot_boost": 40,
    "aimbot": 80,
    "vxh_panel": 100,
    "sensitivity_boost": 30,
}

# ==================== DATABASE ====================
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            credits INTEGER DEFAULT 0,
            is_admin INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            last_login TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            razorpay_order_id TEXT,
            razorpay_payment_id TEXT,
            amount INTEGER,
            credits_added INTEGER,
            status TEXT DEFAULT 'pending',
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS usage_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            feature TEXT NOT NULL,
            credits_used INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS feature_costs (
            feature_key TEXT PRIMARY KEY,
            credits INTEGER NOT NULL,
            display_name TEXT
        )
    """)

    for key, cost in FEATURE_COSTS.items():
        c.execute(
            "INSERT OR IGNORE INTO feature_costs (feature_key, credits, display_name) VALUES (?, ?, ?)",
            (key, cost, key.replace("_", " ").title())
        )

    admin = c.execute("SELECT id FROM users WHERE username = ?", (ADMIN_USERNAME,)).fetchone()
    if not admin:
        c.execute(
            "INSERT INTO users (username, password_hash, credits, is_admin, created_at) VALUES (?, ?, ?, 1, ?)",
            (ADMIN_USERNAME, generate_password_hash(ADMIN_PASSWORD), 99999, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )

    conn.commit()
    conn.close()
    print("[VOIDXHUB] Database ready")

# ==================== HELPERS ====================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"success": False, "message": "Login required"}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id") or not session.get("is_admin"):
            return jsonify({"success": False, "message": "Admin only"}), 403
        return f(*args, **kwargs)
    return decorated

def get_current_user():
    if not session.get("user_id"):
        return None
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    conn.close()
    return user

# ==================== AUTH ROUTES ====================
@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""

    if len(username) < 3:
        return jsonify({"success": False, "message": "Username min 3 characters"}), 400
    if len(password) < 4:
        return jsonify({"success": False, "message": "Password min 4 characters"}), 400

    conn = get_db()
    existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if existing:
        conn.close()
        return jsonify({"success": False, "message": "Username already taken"}), 400

    conn.execute(
        "INSERT INTO users (username, password_hash, credits, created_at) VALUES (?, ?, 0, ?)",
        (username, generate_password_hash(password), datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    user_id = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]
    conn.close()

    session["user_id"] = user_id
    session["username"] = username
    session["is_admin"] = False

    return jsonify({
        "success": True,
        "message": "Registered successfully",
        "user": {"id": user_id, "username": username, "credits": 0}
    })

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if not user or not check_password_hash(user["password_hash"], password):
        conn.close()
        return jsonify({"success": False, "message": "Invalid username or password"}), 401

    conn.execute(
        "UPDATE users SET last_login = ? WHERE id = ?",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user["id"])
    )
    conn.commit()
    conn.close()

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["is_admin"] = bool(user["is_admin"])

    return jsonify({
        "success": True,
        "message": "Login successful",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "credits": user["credits"],
            "is_admin": bool(user["is_admin"])
        }
    })

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True, "message": "Logged out"})

@app.route("/api/me", methods=["GET"])
@login_required
def me():
    user = get_current_user()
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    return jsonify({
        "success": True,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "credits": user["credits"],
            "is_admin": bool(user["is_admin"]),
            "created_at": user["created_at"]
        }
    })

# ==================== CREDITS & FEATURES ====================
@app.route("/api/features", methods=["GET"])
def get_features():
    conn = get_db()
    rows = conn.execute("SELECT * FROM feature_costs").fetchall()
    conn.close()
    features = {r["feature_key"]: {"credits": r["credits"], "name": r["display_name"]} for r in rows}
    return jsonify({"success": True, "features": features})

@app.route("/api/use-feature", methods=["POST"])
@login_required
def use_feature():
    data = request.get_json(silent=True) or {}
    feature = (data.get("feature") or "").strip().lower()

    conn = get_db()
    cost_row = conn.execute("SELECT credits FROM feature_costs WHERE feature_key = ?", (feature,)).fetchone()
    if not cost_row:
        conn.close()
        return jsonify({"success": False, "message": "Feature not found"}), 404

    cost = cost_row["credits"]
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

    if user["credits"] < cost:
        conn.close()
        return jsonify({
            "success": False,
            "message": "Not enough credits",
            "required": cost,
            "balance": user["credits"]
        }), 402

    new_balance = user["credits"] - cost
    conn.execute("UPDATE users SET credits = ? WHERE id = ?", (new_balance, user["id"]))
    conn.execute(
        "INSERT INTO usage_logs (user_id, feature, credits_used, created_at) VALUES (?, ?, ?, ?)",
        (user["id"], feature, cost, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": f"{feature} unlocked",
        "credits_used": cost,
        "new_balance": new_balance
    })

# ==================== RAZORPAY (TEST MODE) ====================
@app.route("/api/packages", methods=["GET"])
def get_packages():
    return jsonify({"success": True, "packages": CREDIT_PACKAGES})

@app.route("/api/create-order", methods=["POST"])
@login_required
def create_order():
    data = request.get_json(silent=True) or {}
    pack_id = data.get("package")

    if pack_id not in CREDIT_PACKAGES:
        return jsonify({"success": False, "message": "Invalid package"}), 400

    pack = CREDIT_PACKAGES[pack_id]

    try:
        import razorpay
        client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
        order = client.order.create({
            "amount": pack["amount"],
            "currency": "INR",
            "payment_capture": 1,
            "notes": {
                "user_id": str(session["user_id"]),
                "credits": str(pack["credits"]),
                "package": pack_id
            }
        })
    except Exception as e:
        return jsonify({"success": False, "message": f"Razorpay error: {str(e)}"}), 500

    conn = get_db()
    conn.execute(
        "INSERT INTO transactions (user_id, razorpay_order_id, amount, credits_added, status, created_at) VALUES (?, ?, ?, ?, 'created', ?)",
        (session["user_id"], order["id"], pack["amount"], pack["credits"], datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "order_id": order["id"],
        "amount": pack["amount"],
        "credits": pack["credits"],
        "key_id": RAZORPAY_KEY_ID
    })

@app.route("/api/verify-payment", methods=["POST"])
@login_required
def verify_payment():
    data = request.get_json(silent=True) or {}
    order_id = data.get("razorpay_order_id")
    payment_id = data.get("razorpay_payment_id")
    signature = data.get("razorpay_signature")

    if not all([order_id, payment_id, signature]):
        return jsonify({"success": False, "message": "Missing payment data"}), 400

    msg = f"{order_id}|{payment_id}"
    generated_sign = hmac.new(
        RAZORPAY_KEY_SECRET.encode(),
        msg.encode(),
        hashlib.sha256
    ).hexdigest()

    if generated_sign != signature:
        return jsonify({"success": False, "message": "Invalid signature"}), 400

    conn = get_db()
    txn = conn.execute(
        "SELECT * FROM transactions WHERE razorpay_order_id = ? AND user_id = ?",
        (order_id, session["user_id"])
    ).fetchone()

    if not txn:
        conn.close()
        return jsonify({"success": False, "message": "Order not found"}), 404

    if txn["status"] == "paid":
        conn.close()
        return jsonify({"success": True, "message": "Already processed", "credits": txn["credits_added"]})

    conn.execute(
        "UPDATE transactions SET status = 'paid', razorpay_payment_id = ? WHERE id = ?",
        (payment_id, txn["id"])
    )
    conn.execute(
        "UPDATE users SET credits = credits + ? WHERE id = ?",
        (txn["credits_added"], session["user_id"])
    )
    conn.commit()

    user = conn.execute("SELECT credits FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    conn.close()

    return jsonify({
        "success": True,
        "message": "Payment successful",
        "credits_added": txn["credits_added"],
        "new_balance": user["credits"]
    })

# ==================== ADMIN ====================
@app.route("/api/admin/users", methods=["GET"])
@admin_required
def admin_users():
    conn = get_db()
    users = conn.execute("SELECT id, username, credits, is_admin, created_at, last_login FROM users ORDER BY id DESC").fetchall()
    conn.close()
    return jsonify({
        "success": True,
        "users": [dict(u) for u in users]
    })

@app.route("/api/admin/add-credits", methods=["POST"])
@admin_required
def admin_add_credits():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    amount = int(data.get("credits", 0))

    if amount == 0:
        return jsonify({"success": False, "message": "Credits cannot be 0"}), 400

    conn = get_db()
    user = conn.execute("SELECT id, credits FROM users WHERE username = ?", (username,)).fetchone()
    if not user:
        conn.close()
        return jsonify({"success": False, "message": "User not found"}), 404

    conn.execute("UPDATE users SET credits = credits + ? WHERE id = ?", (amount, user["id"]))
    conn.commit()
    new_bal = conn.execute("SELECT credits FROM users WHERE id = ?", (user["id"],)).fetchone()["credits"]
    conn.close()

    return jsonify({"success": True, "message": f"Added {amount} credits", "new_balance": new_bal})

@app.route("/api/admin/set-feature-cost", methods=["POST"])
@admin_required
def admin_set_cost():
    data = request.get_json(silent=True) or {}
    feature = data.get("feature")
    credits = int(data.get("credits", 0))

    conn = get_db()
    conn.execute(
        "INSERT OR REPLACE INTO feature_costs (feature_key, credits, display_name) VALUES (?, ?, ?)",
        (feature, credits, feature.replace("_", " ").title())
    )
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Cost updated"})

# ==================== HEALTH ====================
@app.route("/")
def home():
    return jsonify({
        "status": "online",
        "service": "VOIDXHUB Backend",
        "version": "1.0",
        "features": ["auth", "credits", "razorpay-test", "admin"]
    })

# Init
init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
