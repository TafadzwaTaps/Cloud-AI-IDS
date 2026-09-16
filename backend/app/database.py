import os
import psycopg2


def get_connection():
    """
    Connects to Supabase (managed Postgres).

    Preferred: set DATABASE_URL to the connection string from
    Supabase -> Project Settings -> Database -> Connection string.
    On Render, use the "Transaction pooler" string (port 6543) rather
    than the direct connection (port 5432) - Render web services can
    open many short-lived connections, and Supabase's direct connection
    slot limit is low. The pooler string looks like:

        postgresql://postgres.xxxxxxxx:[PASSWORD]@aws-0-region.pooler.supabase.com:6543/postgres

    Falls back to individual DB_* variables if DATABASE_URL isn't set,
    for local development against a plain Postgres instance.
    """
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        return psycopg2.connect(database_url)

    host = os.getenv("DB_HOST")
    port = os.getenv("DB_PORT", "5432")
    database = os.getenv("DB_NAME", "postgres")
    user = os.getenv("DB_USER", "postgres")
    password = os.getenv("DB_PASSWORD")

    if not host or not password:
        raise RuntimeError(
            "No database configuration found. Set DATABASE_URL (recommended - "
            "copy it from Supabase: Project Settings > Database > Connection "
            "string) or set DB_HOST and DB_PASSWORD individually."
        )

    return psycopg2.connect(
        host=host,
        port=port,
        dbname=database,
        user=user,
        password=password,
        sslmode="require",
    )
