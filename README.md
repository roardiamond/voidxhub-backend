<div align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d0d1a,40:4c1d95,100:0d0d1a&height=160&section=header&text=voidxhub-backend&fontSize=42&fontColor=c084fc&animation=twinkling&fontAlignY=40" alt="backend"/>
</div>

<div align="center">
  <img src="https://img.shields.io/badge/API-Live-67e8f9?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Auth-JWT-7c3aed?style=for-the-badge" />
  <img src="https://img.shields.io/badge/DB-SQLite-a855f7?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Host-Render-0d0d1a?style=for-the-badge" />
</div>

---

### Mission

Production API for **VOIDXHUB** — auth, tournaments, admin, payments verify, leaderboard.

```diff
+ Service   : https://voidxhub-backend.onrender.com
+ Clients   : voidxhub.in/www (+ optional mobile)
+ Style     : Secure by default · rate-limited · audit-logged
```

---

### Features

| Area | Endpoints |
|------|-----------|
| **Auth** | register · login · me · change-password · logout-everywhere |
| **Tournaments** | list · detail · register · my registrations |
| **Admin** | create/update/delete tourney · payments · results · stats · audit |
| **Leaderboard** | public standings |
| **Security** | JWT · bcrypt · rate limits · lockout · CORS allowlist |

---

### Deploy (Render)

1. Connect `roardiamond/voidxhub-backend`  
2. **Build:** `pip install -r requirements.txt`  
3. **Start:** `gunicorn app:app --bind 0.0.0.0:$PORT`  
4. Env:

```env
VOIDXHUB_ENV=production
VOIDXHUB_SECRET=<long-random-32+>
VOIDXHUB_ALLOWED_ORIGINS=https://voidxhub.in,https://www.voidxhub.in,capacitor://localhost
```

Seed admin (Shell / one-off):

```bash
python seed.py --username admin --email admin@voidxhub.in
```

---

### Local

```bash
pip install -r requirements.txt
python seed.py
python app.py
# → http://localhost:5000
```

Health: `GET /` → `{ "ok": true, "service": "voidxhub-backend" }`

---

### Stack

Flask · Werkzeug security · SQLite · Gunicorn · JWT  

Website config points here: `VOIDXHUB/www/static/js/config.js` → `API_BASE_URL`

---

<div align="center">
  <b>YashXChi</b> · Full-stack · Cyber-minded · Shipping real systems
</div>
