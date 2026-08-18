CREATE TABLE IF NOT EXISTS messages (
    tenant TEXT NOT NULL,
    message_cid TEXT NOT NULL,
    message_json TEXT NOT NULL,
    indexes_json TEXT NOT NULL,
    PRIMARY KEY (tenant, message_cid)
);

CREATE TABLE IF NOT EXISTS data_blocks (
    data_cid TEXT PRIMARY KEY,
    data BLOB NOT NULL,
    data_size INTEGER NOT NULL,
    ref_count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS data_refs (
    tenant TEXT NOT NULL,
    record_id TEXT NOT NULL,
    data_cid TEXT NOT NULL,
    data_size INTEGER NOT NULL,
    PRIMARY KEY (tenant, record_id, data_cid),
    FOREIGN KEY (data_cid) REFERENCES data_blocks(data_cid)
);

CREATE TABLE IF NOT EXISTS state_index_entries (
    tenant TEXT NOT NULL,
    message_cid TEXT NOT NULL,
    protocol TEXT,
    indexes_json TEXT NOT NULL,
    PRIMARY KEY (tenant, message_cid)
);

CREATE TABLE IF NOT EXISTS event_log_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    epoch TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS event_log_tenant_seq (
    tenant TEXT PRIMARY KEY,
    next_seq INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS event_log_events (
    tenant TEXT NOT NULL,
    seq INTEGER NOT NULL,
    event_json TEXT NOT NULL,
    indexes_json TEXT NOT NULL,
    message_cid TEXT NOT NULL,
    PRIMARY KEY (tenant, seq)
);

CREATE TABLE IF NOT EXISTS resumable_tasks (
    id TEXT PRIMARY KEY,
    task_json TEXT NOT NULL,
    timeout_ms INTEGER NOT NULL,
    retry_count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_secrets (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS sync_checkpoints (
    key TEXT PRIMARY KEY,
    tenant TEXT NOT NULL,
    remote TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    direction TEXT NOT NULL,
    local_root TEXT,
    remote_root TEXT,
    pending_pull_prefixes_json TEXT NOT NULL,
    pending_push_prefixes_json TEXT NOT NULL,
    pull_cursor_json TEXT,
    push_cursor_json TEXT,
    records_pulled INTEGER NOT NULL,
    records_pushed INTEGER NOT NULL,
    bytes_downloaded INTEGER NOT NULL,
    bytes_uploaded INTEGER NOT NULL,
    last_error_json TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sync_dead_letters (
    id TEXT PRIMARY KEY,
    tenant TEXT NOT NULL,
    remote TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    message_cid TEXT,
    entry_json TEXT,
    category TEXT NOT NULL,
    error_json TEXT NOT NULL,
    attempts INTEGER NOT NULL,
    last_attempt_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sync_echo_cache (
    key TEXT PRIMARY KEY,
    remembered_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sync_last_status (
    key TEXT PRIMARY KEY,
    status TEXT NOT NULL
);
