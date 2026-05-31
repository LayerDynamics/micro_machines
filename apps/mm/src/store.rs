//! Local machine registry backed by an embedded `redb` key-value store.
//!
//! Each `mm` invocation is a separate process, so the source of truth for which
//! machines exist (and their IPs/TAPs/state) lives on disk, not in memory. Records
//! are JSON-serialized under their machine name.
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{Context, Result};
use mm_api_types::{ObjectMeta, State};
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

const MACHINES: TableDefinition<&str, &[u8]> = TableDefinition::new("machines");

/// A persisted microVM record (SPEC-1 §3.3 spec + status, slimmed for M1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineRecord {
    pub meta: ObjectMeta,
    pub state: State,
    pub image: String,
    pub vcpus: u8,
    pub memory_mib: u64,
    pub ip: Option<Ipv4Addr>,
    pub tap: Option<String>,
    pub pid: Option<u32>,
}

/// The on-disk machine registry.
pub struct Store {
    db: Database,
}

impl Store {
    /// Open (creating if needed) the registry at `path`, ensuring the table exists.
    pub fn open(path: &Path) -> Result<Self> {
        let db = Database::create(path)
            .with_context(|| format!("opening machine store at {}", path.display()))?;
        // Create the table on first use so reads never fail on a fresh store.
        let txn = db.begin_write()?;
        {
            let _ = txn.open_table(MACHINES)?;
        }
        txn.commit()?;
        Ok(Self { db })
    }

    /// Insert or replace a record (keyed by machine name).
    pub fn put(&self, record: &MachineRecord) -> Result<()> {
        let bytes = serde_json::to_vec(record)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(MACHINES)?;
            table.insert(record.meta.name.as_str(), bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Fetch a record by machine name.
    pub fn get(&self, name: &str) -> Result<Option<MachineRecord>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(MACHINES)?;
        match table.get(name)? {
            Some(value) => Ok(Some(serde_json::from_slice(value.value())?)),
            None => Ok(None),
        }
    }

    /// List all records.
    pub fn list(&self) -> Result<Vec<MachineRecord>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(MACHINES)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (_key, value) = entry?;
            out.push(serde_json::from_slice(value.value())?);
        }
        Ok(out)
    }

    /// Delete a record by name; returns whether it existed.
    pub fn delete(&self, name: &str) -> Result<bool> {
        let txn = self.db.begin_write()?;
        let existed;
        {
            let mut table = txn.open_table(MACHINES)?;
            existed = table.remove(name)?.is_some();
        }
        txn.commit()?;
        Ok(existed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    fn temp_db_path() -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("mm-store-test-{}.redb", uuid::Uuid::new_v4()));
        p
    }

    fn sample(name: &str) -> MachineRecord {
        MachineRecord {
            meta: ObjectMeta::new(name, "default", OffsetDateTime::UNIX_EPOCH),
            state: State::Running,
            image: "docker.io/library/alpine:latest".to_string(),
            vcpus: 2,
            memory_mib: 512,
            ip: Some(Ipv4Addr::new(10, 0, 0, 2)),
            tap: Some("mm-tap0".to_string()),
            pid: Some(1234),
        }
    }

    #[test]
    fn put_get_round_trip() {
        let path = temp_db_path();
        let store = Store::open(&path).unwrap();
        let rec = sample("web-1");
        store.put(&rec).unwrap();
        let got = store.get("web-1").unwrap().unwrap();
        assert_eq!(got, rec);
        assert_eq!(store.get("missing").unwrap(), None);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn list_and_delete() {
        let path = temp_db_path();
        let store = Store::open(&path).unwrap();
        store.put(&sample("a")).unwrap();
        store.put(&sample("b")).unwrap();
        let mut names: Vec<String> = store
            .list()
            .unwrap()
            .into_iter()
            .map(|m| m.meta.name)
            .collect();
        names.sort();
        assert_eq!(names, vec!["a".to_string(), "b".to_string()]);

        assert!(store.delete("a").unwrap());
        assert!(!store.delete("a").unwrap(), "second delete is a no-op");
        assert_eq!(store.list().unwrap().len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn put_replaces_existing() {
        let path = temp_db_path();
        let store = Store::open(&path).unwrap();
        let mut rec = sample("web");
        store.put(&rec).unwrap();
        rec.state = State::Stopped;
        store.put(&rec).unwrap();
        assert_eq!(store.get("web").unwrap().unwrap().state, State::Stopped);
        assert_eq!(store.list().unwrap().len(), 1, "replace, not append");
        let _ = std::fs::remove_file(&path);
    }
}
