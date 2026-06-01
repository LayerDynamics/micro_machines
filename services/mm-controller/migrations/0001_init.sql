-- MicroMachines control-plane schema (SPEC-1 FR-22, FR-7, §3.3).
--
-- Desired state (`machines.spec`) is strongly consistent; observed state
-- (`machines.status`) is eventually consistent, updated from agent reports. The
-- data plane survives a control-plane restart because all of this is durable here
-- and the reconciler re-converges from it (NFR-R2).

CREATE TABLE namespaces (
  name TEXT PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE fleets (
  uid UUID PRIMARY KEY,
  namespace TEXT NOT NULL REFERENCES namespaces(name) ON DELETE CASCADE,
  name TEXT NOT NULL,
  labels JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (namespace, name)
);

CREATE TABLE machines (
  uid UUID PRIMARY KEY,
  namespace TEXT NOT NULL REFERENCES namespaces(name) ON DELETE CASCADE,
  fleet TEXT NOT NULL,
  name TEXT NOT NULL,
  spec JSONB NOT NULL,            -- desired state (strongly consistent)
  status JSONB NOT NULL,          -- observed state (eventually consistent)
  host_id TEXT,                   -- scheduled host, null until placed
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (namespace, fleet, name)
);
CREATE INDEX machines_host_idx ON machines(host_id);
CREATE INDEX machines_ns_idx ON machines(namespace);

CREATE TABLE hosts (
  host_id TEXT PRIMARY KEY,
  capacity JSONB NOT NULL,
  last_heartbeat TIMESTAMPTZ NOT NULL DEFAULT now(),
  healthy BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE rbac_bindings (
  subject TEXT NOT NULL,          -- OIDC subject (sub claim)
  namespace TEXT NOT NULL REFERENCES namespaces(name) ON DELETE CASCADE,
  role TEXT NOT NULL,             -- viewer | operator | admin
  PRIMARY KEY (subject, namespace)
);

CREATE TABLE audit_log (
  id BIGSERIAL PRIMARY KEY,
  at TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor TEXT NOT NULL, namespace TEXT, action TEXT NOT NULL,
  resource TEXT, outcome TEXT NOT NULL
);
