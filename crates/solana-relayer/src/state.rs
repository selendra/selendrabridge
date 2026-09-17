use serde::{Deserialize, Serialize};

/// Resumable scan cursor: the last Solana transaction signature fully handled.
///
/// Persisted after each transaction, so a restart re-scans from there rather than
/// from genesis — and never skips a `Sent` that was observed but not yet stored.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Cursor {
    pub last_signature: Option<String>,
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
        Cursor { last_signature: Some("abc".into()) }.save(&path).unwrap();
        assert_eq!(Cursor::load_or_init(&path).unwrap().last_signature.as_deref(), Some("abc"));
        assert!(!std::path::Path::new(&format!("{path}.tmp")).exists(), "no temp file left behind");
    }

    /// A reader racing the writer must only ever see a complete cursor. With the
    /// truncate-then-write `std::fs::write` it saw an empty file.
    #[test]
    fn a_reader_never_observes_a_partial_cursor() {
        let path = scratch("race");
        let long = "5".repeat(88);
        Cursor { last_signature: Some(long.clone()) }.save(&path).unwrap();

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
            Cursor { last_signature: Some(long.clone()) }.save(&path).unwrap();
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(reader.join().unwrap(), 0, "a reader saw a torn cursor file");
    }
}
