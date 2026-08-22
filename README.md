# VOIDXHUB Backend (Unified)

Single backend for **voidxhub.in** website + Android/iOS Tournament App.

## Features

- User Register / Login (JWT auth – works for website + mobile)
- **Product Orders** (Tools/Services)
  - User places order → pays via UPI → enters UTR
  - Admin verifies → uploads download link
  - Link appears in user’s My Orders
- **Full Tournament System**
  - Create / manage tournaments
  - Registration with team + players (IGN + UID)
  - UPI + UTR payment verification
  - Room ID / Password reveal after verification
  - Results + Leaderboard
  - Admin panel APIs
- Telegram notifications for new orders
- No Credits system (removed)
- No Razorpay (removed)

## Deploy on Render

1. Connect this repo
2. **Build Command**: `pip install -r requirements.txt`
3. **Start Command**: `gunicorn app:app`
4. Environment Variables:

```
VOIDXHUB_ENV=production
VOIDXHUB_SECRET=          # long random string (python -c "import secrets; print(secrets.token_hex(32))")
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your-strong-password
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
VOIDXHUB_ALLOWED_ORIGINS=https://voidxhub.in,https://www.voidxhub.in,capacitor://localhost,https://localhost
```

## Important Notes

- SQLite database is created automatically (`voidxhub.db`)
- On free Render plan the DB resets when the service sleeps/restarts. For production later move to Neon/PostgreSQL.
- First admin user is created automatically from `ADMIN_USERNAME` / `ADMIN_PASSWORD`

## Main API Groups

### Auth
- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET  /api/auth/me`
- `POST /api/auth/change-password`

### Product Orders (Tools / Services)
- `POST /api/orders/create`
- `GET  /api/orders/my`
- `POST /api/orders/lookup`
- Admin: `GET /api/admin/orders`, `POST /api/admin/orders/fulfill`

### Tournaments
- `GET  /api/games`
- `GET  /api/tournaments`
- `GET  /api/tournaments/<id>`
- `POST /api/tournaments/<id>/register`
- `GET  /api/registrations/me`
- `GET  /api/leaderboard`
- Admin create/update/delete + payment verify + results

## Version

2.0 – Tournament-first unified backend
