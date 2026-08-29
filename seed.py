"""Run once to set up the DB with an admin account and sample tournaments.
Usage: python3 seed.py
"""
import sys
import sqlite3
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

from db import get_db, init_db


# Fixed admin credentials as requested
ADMIN_USERNAME = "yashxchi"
ADMIN_EMAIL = "yashxchi@voidxhub.com"
ADMIN_PASSWORD = "7011496531@yash"


def seed():
    init_db()
    conn = get_db()

    existing_admin = conn.execute(
        "SELECT id, username FROM users WHERE role='admin' LIMIT 1"
    ).fetchone()

    if existing_admin:
        # Update existing admin to the requested credentials
        conn.execute(
            "UPDATE users SET username=?, email=?, password_hash=?, role='admin' WHERE id=?",
            (
                ADMIN_USERNAME,
                ADMIN_EMAIL,
                generate_password_hash(ADMIN_PASSWORD),
                existing_admin["id"],
            ),
        )
        conn.commit()
        print("=" * 60)
        print("ADMIN ACCOUNT UPDATED")
        print("=" * 60)
        print(f"  Username: {ADMIN_USERNAME}")
        print(f"  Email:    {ADMIN_EMAIL}")
        print(f"  Password: {ADMIN_PASSWORD}")
        print("=" * 60)
    else:
        try:
            conn.execute(
                "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'admin')",
                (ADMIN_USERNAME, ADMIN_EMAIL, generate_password_hash(ADMIN_PASSWORD)),
            )
            conn.commit()
            print("=" * 60)
            print("ADMIN ACCOUNT CREATED")
            print("=" * 60)
            print(f"  Username: {ADMIN_USERNAME}")
            print(f"  Email:    {ADMIN_EMAIL}")
            print(f"  Password: {ADMIN_PASSWORD}")
            print("=" * 60)
        except sqlite3.IntegrityError:
            # Username/email taken by non-admin — force update that row
            conn.execute(
                "UPDATE users SET email=?, password_hash=?, role='admin' WHERE username=?",
                (ADMIN_EMAIL, generate_password_hash(ADMIN_PASSWORD), ADMIN_USERNAME),
            )
            conn.commit()
            print("=" * 60)
            print("ADMIN ACCOUNT FORCED / UPDATED")
            print("=" * 60)
            print(f"  Username: {ADMIN_USERNAME}")
            print(f"  Email:    {ADMIN_EMAIL}")
            print(f"  Password: {ADMIN_PASSWORD}")
            print("=" * 60)

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
