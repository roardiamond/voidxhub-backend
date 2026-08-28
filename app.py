import os
import re
import json
import sqlite3
import time
import datetime
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

from db import get_db, init_db
from auth import issue_token, login_required, admin_required

app = Flask(__name__)

# Reject oversized request bodies (basic DoS guard)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

# ---------- CORS ----------
# Website (voidxhub.in) + Capacitor Android/iOS app both call this API.
ALLOWED_ORIGINS = {
    "https://voidxhub.in",
    "https://www.voidxhub.in",
    "https://roardiamond.github.io",
    "capacitor://localhost",
    "http://localhost",
    "https://localhost",
    "ionic://localhost",
    "http://127.0.0.1",
    "http://localhost:5000",
} | {o.strip() for o in os.environ.get("VOIDXHUB_ALLOWED_ORIGINS", "").split(",") if o.strip()}


@app.after_request
def add_security_headers(response):
    origin = request.headers.get("Origin")
    if origin and origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, DELETE, OPTIONS"
        response.headers["Vary"] = "Origin"
    elif not origin:
        # Allow same-origin / curl / server-side without Origin
        pass
    else:
        # Still allow common browser cases for GitHub Pages preview
        if origin.endswith(".github.io") or "voidxhub" in origin:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, DELETE, OPTIONS"
            response.headers["Vary"] = "Origin"

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if os.environ.get("VOIDXHUB_ENV") == "production":
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


@app.route("/api/<path:_any>", methods=["OPTIONS"])
def cors_preflight(_any):
    return ("", 204)


@app.route("/")
def health():
    return jsonify({
        "ok": True,
        "service": "voidxhub-backend",
        "message": "Unified backend for voidxhub.in + Android app",
        "version": "2.0",
    })


# ---------- Rate limiting ----------
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


def log_event(event, user_id=None, username=None, detail=""):
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_log (event, user_id, username, ip_address, detail) VALUES (?, ?, ?, ?, ?)",
        (event, user_id, username, client_ip(), detail),
    )
    conn.commit()
    conn.close()


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,20}$")
MODE_PLAYER_COUNTS = {"solo": 1, "duo": 2, "trio": 3, "squad": 4, "4v4": 4, "5v5": 5, "6v6": 6}


def row_to_dict(row):
    return dict(row) if row else None


def slots_filled_count(conn, tournament_id):
    cur = conn.execute(
        "SELECT COUNT(*) c FROM registrations WHERE tournament_id=? AND payment_status != 'rejected'",
        (tournament_id,),
    )
    return cur.fetchone()["c"]


# ---------- Auth ----------

@app.route("/api/auth/register", methods=["POST"])
def register():
    if rate_limited(f"register:{client_ip()}", max_attempts=5, window_seconds=3600):
        return jsonify({"error": "Too many signups from this network. Try again later."}), 429

    data = request.get_json(force=True, silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip().lower()
    phone = (data.get("phone") or "").strip()
    password = data.get("password") or ""

    if not username or not email or not password:
        return jsonify({"error": "Username, email and password are required"}), 400
    if not USERNAME_RE.match(username):
        return jsonify({"error": "Username must be 3-20 characters: letters, numbers, underscores only"}), 400
    if not EMAIL_RE.match(email):
        return jsonify({"error": "Enter a valid email address"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if password.lower() in ("password", "12345678", username.lower()):
        return jsonify({"error": "That password is too easy to guess — pick something less common"}), 400

    conn = get_db()
    try:
        pw_hash = generate_password_hash(password)
        cur = conn.execute(
            "INSERT INTO users (username, email, phone, password_hash) VALUES (?, ?, ?, ?)",
            (username, email, phone, pw_hash),
        )
        conn.commit()
        user = conn.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
        token = issue_token(user)
        log_event("register", user_id=user["id"], username=user["username"])
        return jsonify({
            "token": token,
            "user": {"id": user["id"], "username": user["username"], "email": user["email"], "role": user["role"]}
        }), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or email already taken"}), 409
    finally:
        conn.close()


LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCK_MINUTES = 15


@app.route("/api/auth/login", methods=["POST"])
def login():
    if rate_limited(f"login:{client_ip()}", max_attempts=10, window_seconds=300):
        return jsonify({"error": "Too many login attempts from this network. Try again in a few minutes."}), 429

    data = request.get_json(force=True, silent=True) or {}
    identifier = (data.get("username") or data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE lower(username)=? OR lower(email)=?", (identifier, identifier)
    ).fetchone()

    if user and user["locked_until"]:
        locked_until = datetime.datetime.fromisoformat(user["locked_until"])
        if datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) < locked_until:
            conn.close()
            log_event("login_blocked_locked", user_id=user["id"], username=user["username"])
            return jsonify({"error": f"Account temporarily locked from too many failed attempts. Try again after {locked_until.strftime('%H:%M UTC')}."}), 423

    if not user or not check_password_hash(user["password_hash"], password):
        if user:
            attempts = user["failed_attempts"] + 1
            locked_until = None
            if attempts >= LOGIN_MAX_ATTEMPTS:
                locked_until = (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) + datetime.timedelta(minutes=LOGIN_LOCK_MINUTES)).isoformat()
                log_event("account_locked", user_id=user["id"], username=user["username"])
            conn.execute(
                "UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                (attempts, locked_until, user["id"]),
            )
            conn.commit()
        conn.close()
        log_event("login_failed", username=identifier)
        return jsonify({"error": "Invalid username/email or password"}), 401

    conn.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (user["id"],))
    conn.commit()
    conn.close()

    token = issue_token(user)
    log_event("login", user_id=user["id"], username=user["username"])
    return jsonify({
        "token": token,
        "user": {"id": user["id"], "username": user["username"], "email": user["email"], "role": user["role"]}
    })


@app.route("/api/auth/logout-everywhere", methods=["POST"])
@login_required
def logout_everywhere():
    conn = get_db()
    conn.execute("UPDATE users SET token_version = token_version + 1 WHERE id=?", (request.user["user_id"],))
    conn.commit()
    conn.close()
    log_event("logout_everywhere", user_id=request.user["user_id"], username=request.user["username"])
    return jsonify({"message": "All sessions revoked. Log in again on this device."})


@app.route("/api/auth/change-password", methods=["POST"])
@login_required
def change_password():
    data = request.get_json(force=True, silent=True) or {}
    current = data.get("current_password") or ""
    new = data.get("new_password") or ""

    if len(new) < 8:
        return jsonify({"error": "New password must be at least 8 characters"}), 400

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (request.user["user_id"],)).fetchone()
    if not user or not check_password_hash(user["password_hash"], current):
        conn.close()
        return jsonify({"error": "Current password is incorrect"}), 401

    new_hash = generate_password_hash(new)
    conn.execute(
        "UPDATE users SET password_hash=?, token_version = token_version + 1 WHERE id=?",
        (new_hash, user["id"]),
    )
    conn.commit()
    conn.close()
    log_event("password_changed", user_id=user["id"], username=user["username"])

    fresh_user = get_db().execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
    new_token = issue_token(fresh_user)
    return jsonify({"message": "Password changed. Other devices are now logged out.", "token": new_token})


@app.route("/api/auth/me", methods=["GET"])
@login_required
def me():
    conn = get_db()
    user = conn.execute("SELECT id, username, email, phone, role FROM users WHERE id=?", (request.user["user_id"],)).fetchone()
    conn.close()
    return jsonify(row_to_dict(user))


# ---------- Games ----------

@app.route("/api/games", methods=["GET"])
def list_games():
    conn = get_db()
    games = conn.execute("SELECT * FROM games ORDER BY name").fetchall()
    conn.close()
    return jsonify([dict(g) for g in games])


# ---------- Tournaments ----------

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
    from auth import get_token_from_request, decode_token
    token = get_token_from_request()
    if token:
        payload = decode_token(token)
        if payload:
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

    results = conn.execute(
        "SELECT * FROM results WHERE tournament_id=? ORDER BY position ASC", (tid,)
    ).fetchall()
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
    if rate_limited(f"reg:{request.user['user_id']}", max_attempts=10, window_seconds=600):
        return jsonify({"error": "Too many registration attempts. Slow down and try again shortly."}), 429

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
        return jsonify({"error": f"This is a {tournament['mode']} tournament — {required_count} player{'s' if required_count > 1 else ''} with IGN + UID required"}), 400
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


# ---------- Admin ----------

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
    log_event("admin_create_tournament", user_id=request.user["user_id"], username=request.user["username"], detail=f"tournament_id={tid}")
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
    log_event("admin_update_tournament", user_id=request.user["user_id"], username=request.user["username"], detail=f"tournament_id={tid} fields={list(updates.keys())}")
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
    log_event("admin_delete_tournament", user_id=request.user["user_id"], username=request.user["username"], detail=f"tournament_id={tid}")
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
    log_event("admin_publish_results", user_id=request.user["user_id"], username=request.user["username"], detail=f"tournament_id={tid}")
    return jsonify({"message": "Results published"})


@app.route("/api/admin/audit-log", methods=["GET"])
@admin_required
def admin_audit_log():
    conn = get_db()
    rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


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


@app.route("/api/admin/stats", methods=["GET"])
@admin_required
def admin_stats():
    conn = get_db()
    total_tournaments = conn.execute("SELECT COUNT(*) c FROM tournaments").fetchone()["c"]
    total_users = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    pending_payments = conn.execute("SELECT COUNT(*) c FROM registrations WHERE payment_status='pending'").fetchone()["c"]
    revenue = conn.execute(
        """SELECT COALESCE(SUM(t.entry_fee), 0) rev FROM registrations r
           JOIN tournaments t ON r.tournament_id = t.id WHERE r.payment_status='verified'"""
    ).fetchone()["rev"]
    conn.close()
    return jsonify({
        "total_tournaments": total_tournaments,
        "total_users": total_users,
        "pending_payments": pending_payments,
        "revenue": revenue,
    })


# Ensure DB exists on first request (Render / gunicorn)
@app.before_request
def ensure_db():
    db_path = os.path.join(os.path.dirname(__file__), "voidxhub.db")
    if not os.path.exists(db_path):
        init_db()


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("VOIDXHUB_ENV") != "production")
