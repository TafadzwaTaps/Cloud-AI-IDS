# Deploying to Supabase + Render (no Docker)

## 1. Supabase (database)
1. Create a project at supabase.com.
2. Project -> SQL Editor -> New query -> paste `database/supabase_init.sql` -> Run.
3. Project Settings -> API. You need two values from this page:
   - **Project URL** (`https://xxxxxxxx.supabase.co`) -> `SUPABASE_URL`
   - **service_role key** (under "Project API keys") -> `SUPABASE_SERVICE_KEY`

   The service_role key bypasses Row Level Security, which is the
   right choice for a backend service like this one that owns its own
   data. Never expose the service_role key to the frontend/browser -
   it stays server-side only, as a Render environment variable.

## 2. Render (backend)
1. Push this repo to GitHub/GitLab.
2. Render dashboard -> New -> Web Service -> connect the repo.
   (Or New -> Blueprint and point at this repo, using `render.yaml`.)
3. Settings:
   - Runtime: Python 3
   - Build command: `pip install -r backend/requirements.txt`
   - Start command: `cd backend && uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - Render sets `$PORT` itself - do not hardcode 8000 here.
4. Environment -> Add Environment Variable (both required):
   - `SUPABASE_URL` = the Project URL from step 1.3.
   - `SUPABASE_SERVICE_KEY` = the service_role key from step 1.3.
5. Deploy. Render gives you a URL like `https://cloud-ai-ids-backend.onrender.com`.
6. Sanity check: `curl https://cloud-ai-ids-backend.onrender.com/health` should
   return `{"status": "IDS backend running"}`.
7. Open `https://cloud-ai-ids-backend.onrender.com/` in a browser - this is
   the dashboard itself (`frontend/index.html`), served directly by the
   backend. No separate frontend deploy step needed: `main.py` mounts
   `frontend/` as static files, and `script.js`'s `API_BASE` is set to
   same-origin, so it just works at whatever URL the backend is running on.

## 3. Frontend
Already covered by step 2.7 above - the backend serves it. You don't
need a separate Render Static Site for this project unless you
specifically want the frontend hosted somewhere else than the backend
(e.g. a CDN). If you do that, remember to set `API_BASE` in
`frontend/script.js` back to the full backend URL, since it won't be
same-origin anymore.

## 4. AI Threat Analysis (optional)
The "Analyze" button in the Threat Inspection panel calls OpenAI to
generate a root-cause/remediation report for a flagged flow. To enable it:
1. Get an API key from platform.openai.com.
2. Add `OPENAI_API_KEY` as a Render environment variable (same place as
   the Supabase ones).
3. Optionally set `OPENAI_MODEL` to override the default `gpt-5.4`
   (e.g. `gpt-5.5` once you're ready to switch).

Without `OPENAI_API_KEY` set, the button still appears but shows a
clear "AI analysis not configured" message instead of erroring -
nothing else on the dashboard depends on this being set up.

## Notes
- The RandomForest model files (`model/*.pkl`, ~38MB) are committed to
  the repo and loaded from disk on startup - no separate model hosting
  needed. If they ever exceed GitHub's 100MB file limit, switch to Git
  LFS or load them from Supabase Storage instead.
- Render's free tier spins the service down after inactivity; the first
  request after idle will be slow (cold start) while it reloads the
  ~38MB model into memory. Fine for a thesis demo, worth mentioning as
  a known limitation if you show it live.
