# Deploying to Supabase + Render (no Docker)

## 1. Supabase (database)
1. Create a project at supabase.com.
2. Project -> SQL Editor -> New query -> paste `database/supabase_init.sql` -> Run.
3. Project Settings -> Database -> Connection string -> copy the
   **Transaction pooler** string (port 6543). This is the one to use on
   Render - it's built for lots of short-lived serverless-style
   connections, unlike the direct connection (port 5432), which has a
   low connection-count ceiling on the free tier.
4. It looks like:
   `postgresql://postgres.xxxxxxxx:[YOUR-PASSWORD]@aws-0-<region>.pooler.supabase.com:6543/postgres`
   Fill in your actual database password (the one you set when creating
   the project, not a placeholder).

## 2. Render (backend)
1. Push this repo to GitHub/GitLab.
2. Render dashboard -> New -> Web Service -> connect the repo.
   (Or New -> Blueprint and point at this repo, using `render.yaml`.)
3. Settings:
   - Runtime: Python 3
   - Build command: `pip install -r backend/requirements.txt`
   - Start command: `cd backend && uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - Render sets `$PORT` itself - do not hardcode 8000 here.
4. Environment -> Add Environment Variable:
   - `DATABASE_URL` = the Supabase pooler connection string from step 1.3.
5. Deploy. Render gives you a URL like `https://cloud-ai-ids-backend.onrender.com`.
6. Sanity check: `curl https://cloud-ai-ids-backend.onrender.com/` should
   return `{"status": "IDS backend running"}`.

## 3. Frontend
The `frontend/` folder is static HTML/CSS/JS - no build step.
- Easiest: Render -> New -> Static Site -> point at the same repo,
  publish directory `frontend`.
- In `frontend/script.js`, change `API_BASE` from
  `http://localhost:8000` to your Render backend URL from step 2.5.
- Redeploy the static site after that edit.

## Notes
- The RandomForest model files (`model/*.pkl`, ~38MB) are committed to
  the repo and loaded from disk on startup - no separate model hosting
  needed. If they ever exceed GitHub's 100MB file limit, switch to Git
  LFS or load them from Supabase Storage instead.
- Render's free tier spins the service down after inactivity; the first
  request after idle will be slow (cold start) while it reloads the
  ~38MB model into memory. Fine for a thesis demo, worth mentioning as
  a known limitation if you show it live.
