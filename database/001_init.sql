CREATE TABLE organizations (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    domain TEXT NOT NULL UNIQUE,
    is_fictional BOOLEAN DEFAULT FALSE
);

CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    organization_id INT REFERENCES organizations(id),
    source TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'running',
    started_at TIMESTAMPTZ DEFAULT now(),
    finished_at TIMESTAMPTZ
);

CREATE TABLE organizations (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    domain TEXT NOT NULL UNIQUE,
    is_fictional BOOLEAN DEFAULT FALSE
);

CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    organization_id INT REFERENCES organizations(id),
    source TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'running',
    started_at TIMESTAMPTZ DEFAULT now(),
    finished_at TIMESTAMPTZ
);

CREATE TABLE raw_results (
    id SERIAL PRIMARY KEY,
    scan_id INT REFERENCES scans(id),
    source TEXT NOT NULL,
    payload JSONB NOT NULL,
    collected_at TIMESTAMPTZ DEFAULT now()
);