use serde::{Deserialize, Serialize};

/// Resumable scan cursor: the last Solana transaction signature fully handled.
///
/// Persisted after each transaction, so a restart re-scans from there rather than
/// from genesis — and never skips a `Sent` that was observed but not yet stored.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Cursor {
    pub last_signature: Option<String>,
    /// Gate events this scanner scanned PAST without signing, because they can
    /// never be signed (audit round 6, LOW). See `Scanner::quarantine`.
    ///
    /// Kept here, beside the cursor, because this file is the one record of
    /// "what has been scanned": the cursor alone would say these transactions
    /// were handled, and the log line saying otherwise rotates away. `default`
    /// so a cursor file written before this field loads unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quarantined: Vec<Quarantined>,
}

/// One event the scanner refused to sign and moved past.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quarantined {
    /// The Solana transaction signature carrying the event.
    pub tx: String,
    /// Why it can never be signed, as logged.
    pub reason: String,
}

/// Bound on [`Cursor::quarantined`]. An honest gate never emits an unsignable
/// event, so this is never approached in normal operation; the cap only stops a
/// misbehaving RPC or program from growing the state file without limit.
pub const MAX_QUARANTINED: usize = 1024;

impl Cursor {
    /// Record an event as quarantined. Returns false if `(tx, reason)` is
    /// already recorded — a tick that later fails transiently re-reads the same
    /// transaction, and must not duplicate the entry. Oldest entries are dropped
    /// past [`MAX_QUARANTINED`].
    pub fn quarantine(&mut self, tx: &str, reason: &str) -> bool {
        if self.quarantined.iter().any(|q| q.tx == tx && q.reason == reason) {
            return false;
        }
        self.quarantined.push(Quarantined { tx: tx.to_string(), reason: reason.to_string() });
        if self.quarantined.len() > MAX_QUARANTINED {
            let excess = self.quarantined.len() - MAX_QUARANTINED;
            self.quarantined.drain(..excess);
        }
        true
    }
}

impl Cursor {
    pub fn load_or_init(path: &str) -> anyhow::Result<Cursor> {
        match std::fs::read_to_string(path) {
            Ok(raw) => Ok(serde_json::from_str(&raw)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Cursor::default()),
            Err(e) => Err(anyhow::anyhow!("reading cursor {path}: {e}")),
        }
    }

    /// Persist atomically: write a sibling temp file, flush it to disk, then
    /// rename over the cursor. `std::fs::write` truncated the live file first, so
    /// a crash (or a full disk) mid-write left an empty or partial cursor — which
    /// then failed to parse and stopped the relayer at startup.
    pub fn save(&self, path: &str) -> anyhow::Result<()> {
        use std::io::Write;
        let target = std::path::Path::new(path);
        if let Some(dir) = target.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let tmp = {
            let mut name = target.file_name().unwrap_or_default().to_os_string();
            name.push(".tmp");
            target.with_file_name(name)
        };
        let body = serde_json::to_string_pretty(self)?;
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(body.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, target)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!("solana-relayer-state-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("cursor.json").to_string_lossy().into_owned()
    }

    #[test]
    fn a_saved_cursor_round_trips() {
        let path = scratch("roundtrip");
        Cursor { last_signature: Some("abc".into()), ..Default::default() }.save(&path).unwrap();
        assert_eq!(Cursor::load_or_init(&path).unwrap().last_signature.as_deref(), Some("abc"));
        assert!(!std::path::Path::new(&format!("{path}.tmp")).exists(), "no temp file left behind");
    }

    /// A reader racing the writer must only ever see a complete cursor. With the
    /// truncate-then-write `std::fs::write` it saw an empty file.
    #[test]
    fn a_reader_never_observes_a_partial_cursor() {
        let path = scratch("race");
        let long = "5".repeat(88);
        Cursor { last_signature: Some(long.clone()), ..Default::default() }.save(&path).unwrap();

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader = {
            let (path, stop) = (path.clone(), stop.clone());
            std::thread::spawn(move || {
                let mut torn = 0usize;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    if let Ok(raw) = std::fs::read_to_string(&path) {
                        if serde_json::from_str::<Cursor>(&raw).is_err() {
                            torn += 1;
                        }
                    }
                }
                torn
            })
        };
        for _ in 0..2000 {
            Cursor { last_signature: Some(long.clone()), ..Default::default() }.save(&path).unwrap();
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(reader.join().unwrap(), 0, "a reader saw a torn cursor file");
    }

    /// A cursor file written before `quarantined` existed still loads, and one
    /// with nothing quarantined is written in the old shape.
    #[test]
    fn quarantine_is_backward_compatible_and_deduplicated() {
        let path = scratch("quarantine");
        std::fs::write(&path, r#"{"last_signature":"abc"}"#).unwrap();
        let mut c = Cursor::load_or_init(&path).unwrap();
        assert!(c.quarantined.is_empty());
        assert!(!serde_json::to_string(&c).unwrap().contains("quarantined"));

        assert!(c.quarantine("tx1", "bad"));
        assert!(!c.quarantine("tx1", "bad"), "a re-scan must not duplicate the entry");
        c.save(&path).unwrap();
        let back = Cursor::load_or_init(&path).unwrap();
        assert_eq!(back.quarantined, vec![Quarantined { tx: "tx1".into(), reason: "bad".into() }]);

        for i in 0..MAX_QUARANTINED + 5 {
            c.quarantine(&format!("t{i}"), "r");
        }
        assert_eq!(c.quarantined.len(), MAX_QUARANTINED, "bounded");
    }
}
