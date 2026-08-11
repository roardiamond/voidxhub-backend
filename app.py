from flask import Flask, request, jsonify, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import secrets
import urllib.request
import urllib.parse
from datetime import datetime
from functools import wraps
import hmac
import hashlib

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
CORS(app, supports_credentials=True, origins=["*"])

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID", "rzp_test_xxxxx")
RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET", "your_test_secret")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "8618540927:AAELSHJCjpXYfDwomLTiFHG1AnGs7Ja5UJs")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "7994843509")
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "voidxhub.db")

CREDIT_PACKAGES = {
    "pack_100":  {"credits": 100,  "amount": 5000,   "label": "100 VxH Cr"},
    "pack_250":  {"credits": 250,  "amount": 12500,  "label": "250 VxH Cr"},
    "pack_500":  {"credits": 500,  "amount": 25000,  "label": "500 VxH Cr"},
    "pack_1000": {"credits": 1000, "amount": 50000,  "label": "1000 VxH Cr"},
    "pack_2000": {"credits": 2000, "amount": 100000, "label": "2000 VxH Cr"},
}

FEATURE_COSTS = {
    "esp": 50,
    "headshot_boost": 40,
    "aimbot": 80,
    "vxh_panel": 100,
    "sensitivity_boost": 30,
}

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def send_telegram(text):
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

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        credits INTEGER DEFAULT 0,
        is_admin INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        last_login TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        razorpay_order_id TEXT,
        razorpay_payment_id TEXT,
        amount INTEGER,
        credits_added INTEGER,
        status TEXT DEFAULT 'pending',
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id))""")
    c.execute("""CREATE TABLE IF NOT EXISTS usage_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        feature TEXT NOT NULL,
        credits_used INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id))""")
    c.execute("""CREATE TABLE IF NOT EXISTS feature_costs (
        feature_key TEXT PRIMARY KEY,
        credits INTEGER NOT NULL,
        display_name TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS product_orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_code TEXT UNIQUE NOT NULL,
        user_id INTEGER,
        username TEXT,
        telegram TEXT,
        tool TEXT,
        plan_type TEXT,
        brand TEXT,
        credits INTEGER,
        price_inr INTEGER,
        status TEXT DEFAULT 'pending',
        download_link TEXT,
        admin_note TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id))""")
    for key, cost in FEATURE_COSTS.items():
        c.execute("INSERT OR IGNORE INTO feature_costs (feature_key, credits, display_name) VALUES (?, ?, ?)",
                  (key, cost, key.replace("_", " ").title()))
    admin = c.execute("SELECT id FROM users WHERE username = ?", (ADMIN_USERNAME,)).fetchone()
    if not admin:
        c.execute("INSERT INTO users (username, password_hash, credits, is_admin, created_at) VALUES (?, ?, ?, 1, ?)",
                  (ADMIN_USERNAME, generate_password_hash(ADMIN_PASSWORD), 99999, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    print("[VOIDXHUB] Database ready")

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
    if conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
        conn.close()
        return jsonify({"success": False, "message": "Username already taken"}), 400
    conn.execute("INSERT INTO users (username, password_hash, credits, created_at) VALUES (?, ?, 0, ?)",
                 (username, generate_password_hash(password), datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    user_id = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]
    conn.close()
    session["user_id"] = user_id
    session["username"] = username
    session["is_admin"] = False
    return jsonify({"success": True, "message": "Registered successfully", "user": {"id": user_id, "username": username, "credits": 0}})

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
    conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user["id"]))
    conn.commit()
    conn.close()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["is_admin"] = bool(user["is_admin"])
    return jsonify({"success": True, "message": "Login successful", "user": {"id": user["id"], "username": user["username"], "credits": user["credits"], "is_admin": bool(user["is_admin"])}})

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
    return jsonify({"success": True, "user": {"id": user["id"], "username": user["username"], "credits": user["credits"], "is_admin": bool(user["is_admin"]), "created_at": user["created_at"]}})

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
        return jsonify({"success": False, "message": "Not enough VxH Cr", "required": cost, "balance": user["credits"]}), 402
    new_balance = user["credits"] - cost
    conn.execute("UPDATE users SET credits = ? WHERE id = ?", (new_balance, user["id"]))
    conn.execute("INSERT INTO usage_logs (user_id, feature, credits_used, created_at) VALUES (?, ?, ?, ?)",
                 (user["id"], feature, cost, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": f"{feature} unlocked", "credits_used": cost, "new_balance": new_balance})

@app.route("/api/packages", methods=["GET"])
def get_packages():
    return jsonify({"success": True, "packages": CREDIT_PACKAGES, "rate": "1 INR = 2 VxH Cr"})

@app.route("/api/create-order", methods=["POST"])
@login_required
def create_razorpay_order():
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
            "notes": {"user_id": str(session["user_id"]), "credits": str(pack["credits"]), "package": pack_id}
        })
    except Exception as e:
        return jsonify({"success": False, "message": f"Razorpay error: {str(e)}"}), 500
    conn = get_db()
    conn.execute("INSERT INTO transactions (user_id, razorpay_order_id, amount, credits_added, status, created_at) VALUES (?, ?, ?, ?, 'created', ?)",
                 (session["user_id"], order["id"], pack["amount"], pack["credits"], datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "order_id": order["id"], "amount": pack["amount"], "credits": pack["credits"], "key_id": RAZORPAY_KEY_ID})

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
    generated_sign = hmac.new(RAZORPAY_KEY_SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest()
    if generated_sign != signature:
        return jsonify({"success": False, "message": "Invalid signature"}), 400
    conn = get_db()
    txn = conn.execute("SELECT * FROM transactions WHERE razorpay_order_id = ? AND user_id = ?", (order_id, session["user_id"])).fetchone()
    if not txn:
        conn.close()
        return jsonify({"success": False, "message": "Order not found"}), 404
    if txn["status"] == "paid":
        conn.close()
        return jsonify({"success": True, "message": "Already processed", "credits": txn["credits_added"]})
    conn.execute("UPDATE transactions SET status = 'paid', razorpay_payment_id = ? WHERE id = ?", (payment_id, txn["id"]))
    conn.execute("UPDATE users SET credits = credits + ? WHERE id = ?", (txn["credits_added"], session["user_id"]))
    conn.commit()
    user = conn.execute("SELECT credits FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    conn.close()
    return jsonify({"success": True, "message": "Payment successful", "credits_added": txn["credits_added"], "new_balance": user["credits"]})

# ==================== PRODUCT ORDERS ====================
@app.route("/api/orders/create", methods=["POST"])
def create_product_order():
    data = request.get_json(silent=True) or {}
    tool = (data.get("tool") or "unknown").strip()
    plan_type = (data.get("type") or "public").strip()
    brand = (data.get("brand") or "unknown").strip()
    credits = int(data.get("credits") or 0)
    price_inr = int(data.get("price") or 0)
    telegram = (data.get("telegram") or "").strip()
    username = (data.get("username") or session.get("username") or "guest").strip().lower()
    user_id = session.get("user_id")

    if not telegram:
        return jsonify({"success": False, "message": "Telegram username required"}), 400

    order_code = "VxH-" + secrets.token_hex(4).upper()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    conn.execute("""INSERT INTO product_orders
        (order_code, user_id, username, telegram, tool, plan_type, brand, credits, price_inr, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)""",
        (order_code, user_id, username, telegram, tool, plan_type, brand, credits, price_inr, now))
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
        f"Cost: {credits} VxH Cr (₹{price_inr})\n"
        f"Time: {now}\n\n"
        f"Reply with download link using Admin Panel."
    )
    send_telegram(tg_msg)

    return jsonify({
        "success": True,
        "order_code": order_code,
        "message": "Order placed. Admin will verify and send download link."
    })

@app.route("/api/orders/my", methods=["GET"])
def my_orders():
    username = request.args.get("username") or session.get("username")
    user_id = session.get("user_id")
    conn = get_db()
    if user_id:
        rows = conn.execute("SELECT * FROM product_orders WHERE user_id = ? ORDER BY id DESC", (user_id,)).fetchall()
    elif username:
        rows = conn.execute("SELECT * FROM product_orders WHERE username = ? ORDER BY id DESC", (username.lower(),)).fetchall()
    else:
        conn.close()
        return jsonify({"success": False, "message": "Login or username required"}), 401
    conn.close()
    orders = [dict(r) for r in rows]
    return jsonify({"success": True, "orders": orders})

@app.route("/api/orders/lookup", methods=["POST"])
def lookup_order():
    data = request.get_json(silent=True) or {}
    code = (data.get("order_code") or "").strip().upper()
    telegram = (data.get("telegram") or "").strip().lstrip("@").lower()
    if not code:
        return jsonify({"success": False, "message": "Order code required"}), 400
    conn = get_db()
    row = conn.execute("SELECT * FROM product_orders WHERE order_code = ?", (code,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"success": False, "message": "Order not found"}), 404
    if telegram and row["telegram"].lstrip("@").lower() != telegram:
        return jsonify({"success": False, "message": "Telegram does not match"}), 403
    return jsonify({"success": True, "order": dict(row)})

@app.route("/api/admin/orders", methods=["GET"])
@admin_required
def admin_orders():
    conn = get_db()
    rows = conn.execute("SELECT * FROM product_orders ORDER BY id DESC LIMIT 100").fetchall()
    conn.close()
    return jsonify({"success": True, "orders": [dict(r) for r in rows]})

@app.route("/api/admin/orders/fulfill", methods=["POST"])
@admin_required
def fulfill_order():
    data = request.get_json(silent=True) or {}
    order_code = (data.get("order_code") or "").strip().upper()
    download_link = (data.get("download_link") or "").strip()
    admin_note = (data.get("admin_note") or "").strip()
    if not order_code or not download_link:
        return jsonify({"success": False, "message": "order_code and download_link required"}), 400
    conn = get_db()
    row = conn.execute("SELECT * FROM product_orders WHERE order_code = ?", (order_code,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "Order not found"}), 404
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("UPDATE product_orders SET status = 'delivered', download_link = ?, admin_note = ?, updated_at = ? WHERE order_code = ?",
                 (download_link, admin_note, now, order_code))
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

@app.route("/api/admin/users", methods=["GET"])
@admin_required
def admin_users():
    conn = get_db()
    users = conn.execute("SELECT id, username, credits, is_admin, created_at, last_login FROM users ORDER BY id DESC").fetchall()
    conn.close()
    return jsonify({"success": True, "users": [dict(u) for u in users]})

@app.route("/api/admin/add-credits", methods=["POST"])
@admin_required
def admin_add_credits():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    amount = int(data.get("credits", 0))
    if amount == 0:
        return jsonify({"success": False, "message": "VxH Cr cannot be 0"}), 400
    conn = get_db()
    user = conn.execute("SELECT id, credits FROM users WHERE username = ?", (username,)).fetchone()
    if not user:
        conn.close()
        return jsonify({"success": False, "message": "User not found"}), 404
    conn.execute("UPDATE users SET credits = credits + ? WHERE id = ?", (amount, user["id"]))
    conn.commit()
    new_bal = conn.execute("SELECT credits FROM users WHERE id = ?", (user["id"],)).fetchone()["credits"]
    conn.close()
    return jsonify({"success": True, "message": f"Updated by {amount} VxH Cr", "new_balance": new_bal})

@app.route("/api/admin/set-feature-cost", methods=["POST"])
@admin_required
def admin_set_cost():
    data = request.get_json(silent=True) or {}
    feature = data.get("feature")
    credits = int(data.get("credits", 0))
    conn = get_db()
    conn.execute("INSERT OR REPLACE INTO feature_costs (feature_key, credits, display_name) VALUES (?, ?, ?)",
                 (feature, credits, feature.replace("_", " ").title()))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Cost updated"})

@app.route("/")
def home():
    return jsonify({"status": "online", "service": "VOIDXHUB Backend", "version": "1.2", "currency": "VxH Cr", "rate": "1 INR = 2 VxH Cr"})

init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
