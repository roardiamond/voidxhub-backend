"""Run once to set up the DB with an admin account and sample tournaments.
Usage: python3 seed.py
Usage: python3 seed.py --username youradmin --email you@example.com
"""
import sys
import secrets
import string
import sqlite3
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

from db import get_db, init_db


def generate_strong_password(length=16):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    pw = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*"),
    ]
    pw += [secrets.choice(alphabet) for _ in range(length - len(pw))]
    secrets.SystemRandom().shuffle(pw)
    return "".join(pw)


def parse_args():
    args = {"username": "admin", "email": "admin@voidxhub.in"}
    argv = sys.argv[1:]
    for i, a in enumerate(argv):
        if a == "--username" and i + 1 < len(argv):
            args["username"] = argv[i + 1]
        if a == "--email" and i + 1 < len(argv):
            args["email"] = argv[i + 1]
    return args


def seed():
    init_db()
    conn = get_db()
    args = parse_args()

    existing_admin = conn.execute("SELECT id FROM users WHERE role='admin' LIMIT 1").fetchone()
    if existing_admin:
        print("An admin account already exists — skipping admin creation.")
    else:
        password = generate_strong_password()
        try:
            conn.execute(
                "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'admin')",
                (args["username"], args["email"], generate_password_hash(password)),
            )
            conn.commit()
            print("=" * 60)
            print("ADMIN ACCOUNT CREATED — SAVE THIS NOW, IT WON'T BE SHOWN AGAIN")
            print("=" * 60)
            print(f"  Username: {args['username']}")
            print(f"  Email:    {args['email']}")
            print(f"  Password: {password}")
            print("=" * 60)
        except sqlite3.IntegrityError:
            print("A user with that username/email already exists.")
            conn.close()
            return

    bgmi = conn.execute("SELECT id FROM games WHERE slug='bgmi'").fetchone()
    valorant = conn.execute("SELECT id FROM games WHERE slug='valorant'").fetchone()

    existing = conn.execute("SELECT COUNT(*) c FROM tournaments").fetchone()["c"]
    if existing == 0 and bgmi and valorant:
        tomorrow = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%dT18:00")
        in_three_days = (datetime.now() + timedelta(days=3)).strftime("%Y-%m-%dT20:00")

        conn.execute(
            """INSERT INTO tournaments (title, game_id, mode, description, entry_fee, prize_pool,
                                         slots_total, match_date, upi_id, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'upcoming')""",
            ("Void Squad Showdown #1", bgmi["id"], "squad",
             "4-man squad, erangel classic, top 5 placement + kills split the prize pool.",
             49, 5000, 25, tomorrow, "voidxhub@upi"),
        )
        conn.execute(
            """INSERT INTO tournaments (title, game_id, mode, description, entry_fee, prize_pool,
                                         slots_total, match_date, upi_id, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'upcoming')""",
            ("Valorant 5v5 Clash", valorant["id"], "squad",
             "Single elimination, best of 1, standard competitive ruleset.",
             0, 2000, 16, in_three_days, "voidxhub@upi"),
        )
        print("Seeded 2 sample tournaments.")
    else:
        print("Tournaments already exist (or games missing), skipping sample data.")

    conn.commit()
    conn.close()


if __name__ == "__main__":
    seed()
