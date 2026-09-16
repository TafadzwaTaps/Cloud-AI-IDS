import os
from supabase import create_client, Client

_supabase_client: Client | None = None


def get_supabase() -> Client:
    """
    Returns a cached Supabase client, authenticated with a project API
    key - not a raw Postgres connection string. The DSN-parsing error
    you hit (psycopg2 choking on the Supabase project URL) was because
    DATABASE_URL needs a postgresql:// connection string, not the
    https:// project URL - this sidesteps that whole class of mistake
    by talking to Supabase's REST API instead of Postgres directly.

    Required env vars (Render -> Environment):
      SUPABASE_URL          Project Settings -> API -> Project URL
                             e.g. https://xxxxxxxx.supabase.co
      SUPABASE_SERVICE_KEY  Project Settings -> API -> service_role key
                             (recommended for a backend - bypasses RLS)

    SUPABASE_ANON_KEY / SUPABASE_KEY are accepted as fallbacks if you'd
    rather use the anon key with row-level security policies instead of
    the service role key.
    """
    global _supabase_client
    if _supabase_client is not None:
        return _supabase_client

    url = os.getenv("SUPABASE_URL")
    key = (
        os.getenv("SUPABASE_SERVICE_KEY")
        or os.getenv("SUPABASE_KEY")
        or os.getenv("SUPABASE_ANON_KEY")
    )

    if not url or not key:
        raise RuntimeError(
            "Missing Supabase configuration. Set SUPABASE_URL and "
            "SUPABASE_SERVICE_KEY (or SUPABASE_ANON_KEY) as environment "
            "variables - see database.py for where to find them in the "
            "Supabase dashboard."
        )

    _supabase_client = create_client(url, key)
    return _supabase_client
