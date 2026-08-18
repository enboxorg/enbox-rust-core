CREATE TABLE feed_metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    epoch TEXT NOT NULL CHECK (length(epoch) > 0)
);

CREATE TABLE feed_heads (
    tenant TEXT PRIMARY KEY,
    head INTEGER NOT NULL CHECK (typeof(head) = 'integer' AND head >= 0)
);

CREATE TABLE feed_entries (
    tenant TEXT NOT NULL,
    position INTEGER NOT NULL CHECK (typeof(position) = 'integer' AND position > 0),
    message_cid TEXT NOT NULL,
    indexes_json TEXT NOT NULL,
    fingerprint_scopes_json TEXT NOT NULL,
    PRIMARY KEY (tenant, position),
    UNIQUE (tenant, message_cid)
);

CREATE TABLE feed_fingerprints (
    tenant TEXT NOT NULL,
    domain TEXT NOT NULL,
    value BLOB NOT NULL CHECK (typeof(value) = 'blob' AND length(value) = 32),
    PRIMARY KEY (tenant, domain)
);

CREATE INDEX feed_entries_tenant_position_asc
ON feed_entries (tenant, position ASC);
