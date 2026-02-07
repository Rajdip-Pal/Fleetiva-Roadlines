# 🚚 Fleetiva Roadlines — Logistics & Transport SaaS

## Overview
Fleetiva Roadlines is a production-ready logistics platform for load posting, truck assignment, booking management, and Bilty (LR) generation. It supports role-based access for **Customers**, **Drivers**, and **Admins**, with real-time shipment status updates and printable documentation.

## Key Features
- **Role-Based Access Control (RBAC)** for customers, drivers, and admins.
- **JWT Authentication** with secure password hashing (bcrypt).
- **Load Posting & Matching** to assign available trucks.
- **Booking Management** with shipment status workflow.
- **Real Bilty (LR) Generation** stored in MongoDB and printable as PDF.
- **Payment Tracking** with balance calculations and status updates.
- **OTP Password Recovery** via Redis + Twilio.
- **Centralized Error Handling** and audit logs.

## Tech Stack
**Frontend**
- React + Vite
- Axios with interceptors
- Role-based routing
- Clean UI (CSS modules style)

**Backend**
- Node.js + Express
- MongoDB + Mongoose
- JWT auth
- bcrypt password hashing
- PDFKit for Bilty/Invoice generation

## Project Structure
```text
backend/
  config/
  middleware/
  models/
  routes/
  utils/
frontend/
  src/
    api/
    components/
    context/
    pages/
```

## Environment Variables
### Backend (`backend/.env`)
- `MONGO_URI` — MongoDB Atlas connection string
- `ACCESS_TOKEN_SECRET` — JWT secret
- `ACCESS_TOKEN_TTL` — JWT TTL (e.g., `7d`)
- `FRONTEND_URL` — production frontend URL
- `FRONTEND_PREVIEW_URL` — preview URL (optional)
- `CORS_ORIGINS` — comma-separated CORS allowlist
- `VERCEL_PREVIEW_SUFFIX` — e.g. `.vercel.app`
- `FREIGHT_RATE_PER_TON` — base freight rate
- `OTP_TTL_SECONDS` — OTP expiration (default 600)
- `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_NUMBER` — Twilio SMS
- `REDIS_URL` — Redis connection string
- `SKIP_MONGO` — set `true` to skip DB (not for production)
- `SKIP_FIREBASE` — set `true` if not using Firebase

### Frontend (`frontend/.env`)
- `VITE_API_BASE_URL` — backend API base (e.g. `https://your-backend.onrender.com/api`)
- `VITE_RENDER_SERVICE_NAME` — Render service name for preview URLs
- `VITE_RENDER_SERVICE_URL` — Render base URL
- `VITE_FIREBASE_API_KEY`, `VITE_FIREBASE_AUTH_DOMAIN`, `VITE_FIREBASE_PROJECT_ID`
- `VITE_FIREBASE_STORAGE_BUCKET`, `VITE_FIREBASE_MESSAGING_SENDER_ID`, `VITE_FIREBASE_APP_ID`

### Firebase Authorized Domains
To use Google/Firebase login on Vercel or custom domains, add the deployed URL to **Firebase Console → Authentication → Settings → Authorized domains**.

## Local Development
### Backend
```bash
cd backend
npm install
cp .env.example .env
npm run dev
```

### Frontend
```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

## Deployment
### Backend (Render)
1. Create a new **Web Service** on Render.
2. Set build command: `npm install`
3. Set start command: `npm start`
4. Add environment variables from `backend/.env.example`.
5. Ensure MongoDB Atlas IP allowlist includes Render.

### Frontend (Vercel)
1. Import the `frontend/` project into Vercel.
2. Set `VITE_API_BASE_URL` to the Render backend URL + `/api`.
3. Deploy.

## API Highlights
- `POST /api/auth/register` — Register
- `POST /api/auth/login` — Login
- `GET /api/auth/me` — Current user
- `POST /api/load/post` — Post load (customer)
- `GET /api/load/available` — Loads (admin)
- `POST /api/truck/post` — Post truck (driver)
- `GET /api/match/:loadId` — Match trucks (admin)
- `POST /api/booking/create` — Create booking + Bilty (admin)
- `GET /api/booking/all` — All bookings (admin)
- `GET /api/booking/customer/bookings` — Customer bookings
- `GET /api/booking/driver/bookings` — Driver bookings
- `PATCH /api/booking/:id/status` — Update status (driver)
- `GET /api/booking/:id/bilty` — Download Bilty PDF
- `GET /api/booking/:id/invoice` — Download Invoice PDF

## Security Notes
- Secrets are stored in `.env` only.
- Passwords are hashed with bcrypt.
- JWTs are validated on every protected route.
- CORS and HTTP-only cookies are supported.
