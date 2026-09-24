# CyberShield — Member 3 Frontend

Polished React 18 + Vite + Tailwind SOC dashboard for **Explainable Insider-Threat Anomaly Detector (HTH-CS-07)**.

## Run

```bash
npm install
npm run dev
```

Frontend: `http://localhost:5173`
Backend API base: `http://localhost:8000/api`

## Demo flow

1. Open **Operations Dashboard**.
2. Click **Normal / EMP101** → approved access.
3. Click **Medium / EMP205** → OTP modal opens. Use demo code `123456`.
4. Click **High / EMP302** → session is frozen.
5. Click **Critical / EMP928** → access is blocked.
6. Click **Investigate** on any row → explainability drawer opens.
7. Open **Identity Directory** to show all 35 monitored identities.

If the backend is unavailable, the same simulation flow uses local demo fallbacks so the presentation remains usable.

## Member 4 integration

`App.jsx` owns `selectedIncident`. The built-in explainability drawer can be replaced or extended by Member 4 without changing the dashboard table.
