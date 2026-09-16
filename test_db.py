"""Quick sanity check that SUPABASE_URL / SUPABASE_SERVICE_KEY reach Supabase."""
import sys
sys.path.insert(0, "backend")

from app.database import get_supabase

supabase = get_supabase()
response = supabase.table("intrusion_logs").select("id", count="exact").execute()
print(f"✅ Connected to Supabase. intrusion_logs currently has {response.count} rows.")
