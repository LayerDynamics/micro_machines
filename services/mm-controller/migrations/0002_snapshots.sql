-- Snapshot resource (SPEC-1 FR-18). A point-in-time image of a machine, created on the
-- agent that owns the machine's host and recorded here for listing + restore. Like the
-- `machines` table, this is durable control-plane state (FR-22): it survives a
-- control-plane restart.
CREATE TABLE snapshots (
  uid UUID PRIMARY KEY,
  namespace TEXT NOT NULL REFERENCES namespaces(name) ON DELETE CASCADE,
  machine TEXT NOT NULL,            -- source machine name
  name TEXT NOT NULL,               -- snapshot id (worker-allocated, sortable timestamp)
  kind TEXT NOT NULL,               -- 'full' | 'branch'
  host_id TEXT NOT NULL,            -- host the snapshot's files live on
  memory_mib BIGINT NOT NULL,
  status TEXT NOT NULL,             -- 'creating' | 'ready' | 'failed'
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (namespace, machine, name)
);
CREATE INDEX snapshots_ns_idx ON snapshots(namespace);
CREATE INDEX snapshots_machine_idx ON snapshots(namespace, machine);
