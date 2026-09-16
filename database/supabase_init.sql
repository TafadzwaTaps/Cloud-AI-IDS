-- Run this once in the Supabase SQL Editor (Project -> SQL Editor -> New query)
-- after creating your project. Supabase projects already have a "postgres"
-- database, so there's no CREATE DATABASE step like the old SQL Server script.

CREATE TABLE IF NOT EXISTS intrusion_logs (
    id SERIAL PRIMARY KEY,
    total_records INT NOT NULL,
    attacks_detected INT NOT NULL,
    benign_detected INT NOT NULL,
    attack_ratio FLOAT NOT NULL,
    detected_at TIMESTAMPTZ DEFAULT NOW()
);

-- Speeds up the "last 10 scans" / history queries in /stats/performance
-- and /stats/history as the table grows.
CREATE INDEX IF NOT EXISTS idx_intrusion_logs_id_desc ON intrusion_logs (id DESC);
