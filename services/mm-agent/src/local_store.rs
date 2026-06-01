//! The agent's local machine registry (SPEC-1 NFR-R2).
//!
//! An agent persists what it owns to a local `redb` database so a restart can
//! re-discover its running microVMs and report them — without waiting for or
//! depending on the controller. This is the data-plane survival mechanism: the
//! controller can be down or restarting while the agent keeps its machines and their
//! observed state locally, then reconciles back when the controller returns.
use anyhow::{Context, Result};
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

const MACHINES: TableDefinition<&str, &[u8]> = TableDefinition::new("agent_machines");

/// A machine this agent owns, keyed by the controller's stable `uid`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalMachine {
    pub uid: String,
    pub namespace: String,
    pub name: String,
    pub image: String,
    pub vcpus: u32,
    pub memory_mib: u64,
    pub ip: Option<String>,
    /// PID of the jailed worker serving this machine (for stop/health).
    pub pid: Option<u32>,
    /// Last observed lifecycle state name (snake_case, matching `mm_api_types::State`).
    pub state: String,
}

/// On-disk registry of the machines this agent is responsible for.
pub struct LocalStore {
    db: Database,
}

impl LocalStore {
    /// Open (creating if needed) the registry at `path`, ensuring the table exists.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let db = Database::create(path.as_ref())
            .with_context(|| format!("opening agent store at {}", path.as_ref().display()))?;
        // Materialize the table so reads never fail on a fresh database.
        let txn = db.begin_write()?;
        {
            let _ = txn.open_table(MACHINES)?;
        }
        txn.commit()?;
        Ok(Self { db })
    }

    /// Insert or replace a machine record.
    pub fn put(&self, machine: &LocalMachine) -> Result<()> {
        let bytes = serde_json::to_vec(machine).context("serializing machine record")?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(MACHINES)?;
            table.insert(machine.uid.as_str(), bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Fetch a machine by uid.
    pub fn get(&self, uid: &str) -> Result<Option<LocalMachine>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(MACHINES)?;
        match table.get(uid)? {
            Some(v) => Ok(Some(
                serde_json::from_slice(v.value()).context("deserializing machine record")?,
            )),
            None => Ok(None),
        }
    }

    /// All machines this agent owns (used to recover state + compute capacity).
    pub fn list(&self) -> Result<Vec<LocalMachine>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(MACHINES)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (_, v) = entry?;
            out.push(serde_json::from_slice(v.value()).context("deserializing machine record")?);
        }
        Ok(out)
    }

    /// Remove a machine record.
    pub fn delete(&self, uid: &str) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(MACHINES)?;
            table.remove(uid)?;
        }
        txn.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(uid: &str) -> LocalMachine {
        LocalMachine {
            uid: uid.into(),
            namespace: "team-a".into(),
            name: "web".into(),
            image: "docker.io/library/alpine:latest".into(),
            vcpus: 2,
            memory_mib: 512,
            ip: Some("10.0.0.2".into()),
            pid: Some(4242),
            state: "running".into(),
        }
    }

    fn temp_db() -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "mm-agent-store-test-{}-{}.redb",
            std::process::id(),
            // distinct per call within a process without a clock/rng dep
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        p
    }
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    #[test]
    fn put_get_list_delete_roundtrip() {
        let path = temp_db();
        let store = LocalStore::open(&path).unwrap();

        assert!(store.get("u1").unwrap().is_none());
        store.put(&sample("u1")).unwrap();
        store.put(&sample("u2")).unwrap();

        assert_eq!(store.get("u1").unwrap().unwrap(), sample("u1"));
        let mut uids: Vec<String> = store.list().unwrap().into_iter().map(|m| m.uid).collect();
        uids.sort();
        assert_eq!(uids, vec!["u1".to_string(), "u2".to_string()]);

        store.delete("u1").unwrap();
        assert!(store.get("u1").unwrap().is_none());
        assert_eq!(store.list().unwrap().len(), 1);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn survives_reopen() {
        // The point of the local store: a restart re-discovers owned machines.
        let path = temp_db();
        {
            let store = LocalStore::open(&path).unwrap();
            store.put(&sample("persist")).unwrap();
        }
        let reopened = LocalStore::open(&path).unwrap();
        assert_eq!(reopened.get("persist").unwrap().unwrap(), sample("persist"));
        let _ = std::fs::remove_file(&path);
    }
}
