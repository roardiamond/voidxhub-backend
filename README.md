# VOIDXHUB Backend

**Unified backend** for **voidxhub.in** website + **vxhtourneyv2** Android app.

Admin creates a tournament on the website → it appears instantly in the app (same API + same database).

## Features

- JWT auth (register / login / change password / logout-everywhere)
- Tournament CRUD + registration + payment verify + results + leaderboard
- Admin stats + audit log
- CORS for voidxhub.in + Capacitor
- SQLite (simple, portable)

## Render Deploy

1. Connect `roardiamond/voidxhub-backend`
2. **Build**: `pip install -r requirements.txt`
3. **Start**: `gunicorn app:app --bind 0.0.0.0:$PORT`
4. Environment variables:

```
VOIDXHUB_ENV=production
VOIDXHUB_SECRET=<long-random-hex-32-bytes>
VOIDXHUB_ALLOWED_ORIGINS=https://voidxhub.in,https://www.voidxhub.in,capacitor://localhost
```

After first deploy, open a shell (or one-time job) and run:

```bash
python seed.py --username admin --email admin@voidxhub.in
```

Save the printed password.

## Local

```bash
pip install -r requirements.txt
python seed.py
python app.py
```

API base: `http://localhost:5000`

## Clients already synced

- Website: `VOIDXHUB/www/static/js/config.js` → `API_BASE_URL = https://voidxhub-backend.onrender.com`
- App: `vxhtourneyv2/www/static/js/config.js` → same URL

---

Maintainer: YashXChi
