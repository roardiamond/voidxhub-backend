# VOIDXHUB Backend

Unified backend for **voidxhub.in** website and the Android/iOS Tournaments app.

Built with Python for reliability, simplicity, and easy deployment.

## Features

### Authentication
- User registration & login (JWT based)
- Works for both website and mobile clients
- Password change support

### Product Orders (Tools / Services)
- Create order → UPI payment → enter UTR
- Admin verification flow
- Download link delivery after approval
- Order history for users

### Tournament System
- Create & manage tournaments
- Team registration with player details (IGN + UID)
- UPI + UTR payment verification
- Room ID / Password reveal after verification
- Results & leaderboard
- Full admin APIs

### Other
- Telegram notifications for new orders
- CORS configured for web + Capacitor
- SQLite for easy start (can migrate to PostgreSQL later)

## Tech Stack

- Python + Flask / Gunicorn
- JWT Authentication
- SQLite (default)
- Telegram Bot API for notifications

## Deployment (Render)

1. Connect this repository
2. **Build Command**: `pip install -r requirements.txt`
3. **Start Command**: `gunicorn app:app`
4. Set environment variables:

```
VOIDXHUB_ENV=production
VOIDXHUB_SECRET=<long-random-string>
ADMIN_USERNAME=admin
ADMIN_PASSWORD=<strong-password>
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
VOIDXHUB_ALLOWED_ORIGINS=https://voidxhub.in,https://www.voidxhub.in,capacitor://localhost
```

## Local Setup

```bash
git clone https://github.com/roardiamond/voidxhub-backend.git
cd voidxhub-backend
pip install -r requirements.txt
python app.py
```

## Main API Groups

### Auth
- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET  /api/auth/me`

### Orders
- `POST /api/orders/create`
- `GET  /api/orders/my`
- Admin fulfill endpoints

### Tournaments
- Full CRUD + registration + leaderboard + results

## Version

2.0 – Tournament-first unified backend

---

**Maintainer**: YashXChi  
Clean, reliable backend systems.
