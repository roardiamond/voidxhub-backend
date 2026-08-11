# VOIDXHUB Backend

Full backend for voidxhub.in

- User Register / Login
- Credits System
- Razorpay Test Mode
- SQL Database
- Admin APIs

## Deploy on Render

1. New Web Service → Connect this repo
2. Build: `pip install -r requirements.txt`
3. Start: `gunicorn app:app`
4. Environment Variables:

```
SECRET_KEY=any-long-random-string
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your-strong-password
RAZORPAY_KEY_ID=rzp_test_xxxxxxxx
RAZORPAY_KEY_SECRET=your_test_secret_key
```

## API Endpoints

### Auth
- `POST /api/register` → `{ "username": "...", "password": "..." }`
- `POST /api/login` → `{ "username": "...", "password": "..." }`
- `POST /api/logout`
- `GET  /api/me` (login required)

### Credits & Features
- `GET  /api/features` → feature costs
- `POST /api/use-feature` → `{ "feature": "esp" }` (deducts credits)

### Razorpay (Test Mode)
- `GET  /api/packages`
- `POST /api/create-order` → `{ "package": "pack_100" }`
- `POST /api/verify-payment` → razorpay response

### Admin
- `GET  /api/admin/users`
- `POST /api/admin/add-credits` → `{ "username": "...", "credits": 100 }`
- `POST /api/admin/set-feature-cost` → `{ "feature": "esp", "credits": 50 }`

## Credit Packages (editable in app.py)

| Package    | Credits | Price  |
|------------|---------|--------|
| pack_100   | 100     | ₹49    |
| pack_300   | 300     | ₹129   |
| pack_700   | 700     | ₹249   |
| pack_1500  | 1500    | ₹499   |

## Default Feature Costs

| Feature            | Credits |
|--------------------|---------|
| esp                | 50      |
| headshot_boost     | 40      |
| aimbot             | 80      |
| vxh_panel          | 100     |
| sensitivity_boost  | 30      |
