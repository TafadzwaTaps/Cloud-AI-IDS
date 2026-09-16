"""Quick sanity check that DATABASE_URL / DB_* env vars reach Supabase."""
import sys
sys.path.insert(0, "backend")

from app.database import get_connection

conn = get_connection()
cur = conn.cursor()
cur.execute("SELECT COUNT(*) FROM intrusion_logs")
print(f"✅ Connected to Supabase. intrusion_logs currently has {cur.fetchone()[0]} rows.")
conn.close()
