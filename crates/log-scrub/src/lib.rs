//! Keep credentials out of the logs.
//!
//! Every node logs transport failures, and a transport failure carries the URL
//! it failed on. On the live mesh that meant the provider key, in the clear, in
//! `docker logs` — 43 lines across five services on mesh9's first three days
//! (audit 2026-09-16, found live 2026-09-21):
//!
//! ```text
//! WARN validator: get_logs failed; retrying chain_id=11155111
//!      error=… error sending request for url (https://eth-sepolia.rpc.example/v2/alch_…)
//! ```
//!
//! Redacting at each `warn!` cannot work: the URL is inside an error built by
//! `reqwest` several layers down, and the next call site added forgets again.
//! So the scrub happens at the ONE place every line passes through — the
//! subscriber's writer ([`init`]).
//!
//! Two rules, both conservative, because a log that hides the failing endpoint
//! is its own kind of outage:
//!
//! 1. **Inside a URL** (and only there), an opaque path segment or query value
//!    is replaced by `<redacted>`. "Opaque" means ≥16 characters of
//!    `[A-Za-z0-9_-]`, which is what an API key looks like and what an English
//!    path segment does not. The scheme, host and port always survive, so
//!    `https://eth-sepolia.rpc.example/v2/<redacted>` still names the
//!    provider, the chain and the failure. `http://sig-store:8080/submissions?
//!    pending=refunds&chain_id_from=11155111` is untouched.
//! 2. **Registered secrets** ([`register_secret`]) are replaced wherever they
//!    appear, URL or not. That covers bearer tokens, which have no syntax to
//!    recognise them by.
//!
//! Base58 Solana pubkeys (32–44 opaque characters) are NOT inside a URL, so
//! rule 1 leaves them alone; `pubkey=9panXgAHfaNo4b7n21j3wgR5kQUGUC7Ckjz5EtoHCegg`
//! is still readable. Likewise submissionIds, addresses and tx hashes.
//!
//! This is defence in depth, not a licence to log secrets: it cannot scrub what
//! a `Debug` impl mangles, and it is not a reason to put a key on a command
//! line (see `solana-relayer`'s `--rpc-env`).

use std::borrow::Cow;
use std::io::{self, Write};
use std::sync::{OnceLock, RwLock};

/// Shortest registered secret worth replacing. Below this a "secret" is more
/// likely to be a common word that would blank out half the line.
const MIN_SECRET_LEN: usize = 8;

/// Shortest opaque URL component treated as a credential. `v2`, `submissions`
/// and `refund-candidates` stay; a 25-character key does not.
const MIN_OPAQUE_LEN: usize = 16;

const REDACTED: &str = "<redacted>";

fn secrets() -> &'static RwLock<Vec<String>> {
    static SECRETS: OnceLock<RwLock<Vec<String>>> = OnceLock::new();
    SECRETS.get_or_init(|| RwLock::new(Vec::new()))
}

/// Register a literal that must never be logged (a bearer token, a password).
///
/// Values shorter than 8 bytes are ignored: too short to be a credential worth
/// this, and long enough to wreck a line if it were a common word. Registering
/// the same value twice is a no-op, and a poisoned lock is ignored rather than
/// panicking — failing to register is better than taking the process down.
pub fn register_secret(value: impl AsRef<str>) {
    let value = value.as_ref();
    if value.len() < MIN_SECRET_LEN {
        return;
    }
    if let Ok(mut list) = secrets().write() {
        if !list.iter().any(|s| s == value) {
            list.push(value.to_string());
        }
    }
}

/// Replace credentials in one line of log output.
///
/// Borrowed unchanged when there is nothing to hide, which is the common case.
pub fn scrub(line: &str) -> Cow<'_, str> {
    let out = scrub_urls(line);
    let list = match secrets().read() {
        Ok(list) => list,
        Err(_) => return out,
    };
    if list.is_empty() {
        return out;
    }
    let mut owned: Option<String> = None;
    for secret in list.iter() {
        let current: &str = owned.as_deref().unwrap_or(&out);
        if current.contains(secret.as_str()) {
            owned = Some(current.replace(secret.as_str(), REDACTED));
        }
    }
    match owned {
        Some(s) => Cow::Owned(s),
        None => out,
    }
}

/// True for a URL component that looks like a credential rather than a name.
///
/// Length and charset alone are not enough: `refund-candidates` is 17 ASCII
/// characters and is one of our own endpoints. A credential also mixes in
/// entropy, so this additionally wants a digit AND (an uppercase letter or
/// several digits) — `alch_Ex4mpl3K3y-N0t-Re4l7` qualifies, `refund-candidates`
/// and `solana-signature-status` do not.
///
/// A `0x`-prefixed component is exempt: that is on-chain data (a submissionId,
/// a tx hash, an address), never a credential, and blanking it would hide the
/// one identifier that makes the line worth keeping.
fn is_opaque(component: &str) -> bool {
    if component.len() < MIN_OPAQUE_LEN || component.starts_with("0x") || component.starts_with("0X") {
        return false;
    }
    if !component.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return false;
    }
    let digits = component.chars().filter(char::is_ascii_digit).count();
    let has_letter = component.chars().any(|c| c.is_ascii_alphabetic());
    let has_upper = component.chars().any(|c| c.is_ascii_uppercase());
    has_letter && digits > 0 && (has_upper || digits >= 4)
}

/// Rewrite every `http(s)://…` run in `line`, keeping scheme/host/port.
fn scrub_urls(line: &str) -> Cow<'_, str> {
    let mut out: Option<String> = None;
    // Index into `line` of the first byte not yet copied into `out`. Kept
    // separately from `out.len()`, which drifts as soon as a replacement is a
    // different length than what it replaced.
    let mut copied = 0usize;
    let mut cursor = 0usize;
    while let Some(offset) = find_scheme(&line[cursor..]) {
        let start = cursor + offset;
        let len = url_len(&line[start..]);
        if let Some(clean) = scrub_one_url(&line[start..start + len]) {
            let buf = out.get_or_insert_with(String::new);
            buf.push_str(&line[copied..start]);
            buf.push_str(&clean);
            copied = start + len;
        }
        cursor = start + len;
    }
    match out {
        Some(mut buf) => {
            buf.push_str(&line[copied..]);
            Cow::Owned(buf)
        }
        None => Cow::Borrowed(line),
    }
}

fn find_scheme(s: &str) -> Option<usize> {
    let http = s.find("http://");
    let https = s.find("https://");
    match (http, https) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

/// How far the URL runs. Stops at whitespace or a delimiter the surrounding log
/// line supplies — `reqwest` prints URLs inside `(…)`, ours land in `url=…` and
/// quoted JSON.
fn url_len(s: &str) -> usize {
    s.find(|c: char| c.is_whitespace() || matches!(c, ')' | '"' | '\'' | '>' | ',' | '`'))
        .unwrap_or(s.len())
}

/// `None` when the URL holds nothing worth hiding.
fn scrub_one_url(url: &str) -> Option<String> {
    let scheme_end = url.find("://")? + 3;
    let (scheme, after) = url.split_at(scheme_end);
    let authority_end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let (authority, path_and_query) = after.split_at(authority_end);
    let mut changed = false;

    // `scheme://user:pass@host` — the whole userinfo goes, it is only ever credentials.
    let authority = match authority.rfind('@') {
        Some(at) => {
            changed = true;
            Cow::Owned(format!("{REDACTED}@{}", &authority[at + 1..]))
        }
        None => Cow::Borrowed(authority),
    };

    let (path, query, fragment) = split_path(path_and_query);
    let mut out_path = String::with_capacity(path.len());
    for segment in path.split_inclusive('/') {
        let (name, slash) = match segment.strip_suffix('/') {
            Some(name) => (name, "/"),
            None => (segment, ""),
        };
        if is_opaque(name) {
            changed = true;
            out_path.push_str(REDACTED);
        } else {
            out_path.push_str(name);
        }
        out_path.push_str(slash);
    }

    let out_query = query.map(|q| {
        let mut buf = String::with_capacity(q.len());
        for (i, pair) in q.split('&').enumerate() {
            if i > 0 {
                buf.push('&');
            }
            match pair.split_once('=') {
                // A value is hidden when it looks opaque OR its key names a
                // credential — `?token=abc` is short but still a token.
                Some((k, v)) if is_opaque(v) || is_secret_key(k) => {
                    changed = true;
                    buf.push_str(k);
                    buf.push('=');
                    buf.push_str(REDACTED);
                }
                _ => buf.push_str(pair),
            }
        }
        buf
    });

    if !changed {
        return None;
    }
    let mut out = String::with_capacity(url.len());
    out.push_str(scheme);
    out.push_str(&authority);
    out.push_str(&out_path);
    if let Some(q) = out_query {
        out.push('?');
        out.push_str(&q);
    }
    if let Some(f) = fragment {
        out.push('#');
        out.push_str(f);
    }
    Some(out)
}

fn split_path(s: &str) -> (&str, Option<&str>, Option<&str>) {
    let (before_fragment, fragment) = match s.split_once('#') {
        Some((a, b)) => (a, Some(b)),
        None => (s, None),
    };
    match before_fragment.split_once('?') {
        Some((p, q)) => (p, Some(q), fragment),
        None => (before_fragment, None, fragment),
    }
}

fn is_secret_key(key: &str) -> bool {
    let key = key.trim_start_matches('?').to_ascii_lowercase();
    ["token", "key", "apikey", "api_key", "auth", "secret", "password", "passwd", "pass", "access_token"]
        .contains(&key.as_str())
}

/// A writer that scrubs whole lines on their way to `inner`.
///
/// Line-buffered on purpose: the formatter may split one event across writes,
/// and scrubbing half a URL would miss it. Anything still buffered when the
/// writer drops (a line with no trailing newline) is scrubbed and flushed then.
pub struct ScrubWriter<W: Write> {
    inner: W,
    buf: Vec<u8>,
}

impl<W: Write> ScrubWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner, buf: Vec::new() }
    }

    fn drain_lines(&mut self) -> io::Result<()> {
        while let Some(nl) = self.buf.iter().position(|&b| b == b'\n') {
            let line = self.buf.drain(..=nl).collect::<Vec<u8>>();
            self.write_scrubbed(&line)?;
        }
        Ok(())
    }

    fn write_scrubbed(&mut self, line: &[u8]) -> io::Result<()> {
        // Non-UTF-8 output is passed through rather than dropped: it cannot
        // contain a credential this can recognise, and losing it hides an
        // incident.
        match std::str::from_utf8(line) {
            Ok(text) => self.inner.write_all(scrub(text).as_bytes()),
            Err(_) => self.inner.write_all(line),
        }
    }
}

impl<W: Write> Write for ScrubWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        self.drain_lines()?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.drain_lines()?;
        self.inner.flush()
    }
}

impl<W: Write> Drop for ScrubWriter<W> {
    fn drop(&mut self) {
        if !self.buf.is_empty() {
            let rest = std::mem::take(&mut self.buf);
            let _ = self.write_scrubbed(&rest);
        }
        let _ = self.inner.flush();
    }
}

/// `MakeWriter` wrapper: `tracing_subscriber::fmt().with_writer(scrubbed(io::stdout))`.
#[derive(Clone, Copy, Debug)]
pub struct Scrubbed<M>(M);

/// Wrap a `MakeWriter` so every line it emits is scrubbed.
pub fn scrubbed<M>(make: M) -> Scrubbed<M> {
    Scrubbed(make)
}

impl<'a, M: tracing_subscriber::fmt::MakeWriter<'a>> tracing_subscriber::fmt::MakeWriter<'a> for Scrubbed<M> {
    type Writer = ScrubWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        ScrubWriter::new(self.0.make_writer())
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        ScrubWriter::new(self.0.make_writer_for(meta))
    }
}

/// Install the standard subscriber for a node binary: env filter, scrubbed
/// stdout. `default_filter` is used when `RUST_LOG` says nothing.
///
/// Every binary in this repo goes through here, so a credential cannot reach
/// the logs by way of a binary that forgot to opt in.
pub fn init(default_filter: &str) {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_filter)),
        )
        .with_writer(scrubbed(io::stdout))
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim from `docker logs testnet-mesh9-validator-val-1-1`, key altered.
    const LIVE_VALIDATOR: &str = "WARN validator: get_logs failed; retrying chain_id=11155111 error=all 1 RPC endpoints failed for get_logs_confirmed: error sending request for url (https://eth-sepolia.rpc.example/v2/alch_Ex4mpl3K3y-N0t-Re4l7)";

    #[test]
    fn the_live_leak_is_closed_and_the_endpoint_still_named() {
        let out = scrub(LIVE_VALIDATOR);
        assert!(!out.contains("alch_Ex4mpl3K3y-N0t-Re4l7"), "{out}");
        // Everything an operator needs to act on the failure survives.
        assert!(out.contains("https://eth-sepolia.rpc.example/v2/<redacted>"), "{out}");
        assert!(out.contains("chain_id=11155111"), "{out}");
        assert!(out.contains("get_logs failed"), "{out}");
    }

    #[test]
    fn a_solana_rpc_url_and_a_pubkey_are_told_apart() {
        let line = "WARN solana_price_keeper: tick failed error=AccountNotFound: pubkey=9panXgAHfaNo4b7n21j3wgR5kQUGUC7Ckjz5EtoHCegg: error sending request for url (https://solana-devnet.rpc.example/v2/alch_Ex4mpl3K3y-N0t-Re4l7): operation timed out";
        let out = scrub(line);
        assert!(!out.contains("alch_Ex4mpl3K3y-N0t-Re4l7"), "{out}");
        // The account being read is not a secret and is the whole diagnosis.
        assert!(out.contains("pubkey=9panXgAHfaNo4b7n21j3wgR5kQUGUC7Ckjz5EtoHCegg"), "{out}");
    }

    #[test]
    fn an_internal_url_with_readable_parts_is_untouched() {
        let line = "WARN keeper: pending_refunds read failed error=http: error sending request for url (http://sig-store:8080/submissions?pending=refunds&chain_id_from=11155111)";
        assert!(matches!(scrub(line), Cow::Borrowed(_)), "should not allocate: {line}");
        let line2 = "GET http://sig-store:8080/refund-candidates?limit=500&offset=0";
        assert_eq!(scrub(line2), line2);
    }

    #[test]
    fn userinfo_and_named_credential_parameters_go() {
        let out = scrub("postgres check via http://bridge:hunter2@db:5432/bridge and https://x.test/p?token=abc&limit=5");
        assert!(out.contains("http://<redacted>@db:5432/bridge"), "{out}");
        assert!(out.contains("token=<redacted>"), "{out}");
        assert!(out.contains("limit=5"), "{out}");
    }

    #[test]
    fn a_registered_token_is_replaced_anywhere_in_the_line() {
        // 8+ chars, and not a substring of the other tests' text.
        register_secret("zzq7Rk4sTokenValue");
        let out = scrub("store rejected the call token=zzq7Rk4sTokenValue (401)");
        assert!(!out.contains("zzq7Rk4sTokenValue"), "{out}");
        assert!(out.contains("(401)"), "{out}");
        // Too short to register: ignored rather than blanking common words.
        register_secret("abc");
        assert_eq!(scrub("abc is fine"), "abc is fine");
    }

    #[test]
    fn several_urls_on_one_line_are_each_handled() {
        let out = scrub(
            "rotating https://a.test/v2/alch_Ex4mpl3K3y-N0t-Re4l7 -> https://b.test/v2/k3yk3yk3yk3yk3yk3y (ok) http://sig-store:8080/submissions",
        );
        assert_eq!(
            out,
            "rotating https://a.test/v2/<redacted> -> https://b.test/v2/<redacted> (ok) http://sig-store:8080/submissions"
        );
    }

    /// The heuristic's two edges, both seen in this repo's own URLs.
    #[test]
    fn our_own_long_endpoint_names_and_on_chain_ids_survive() {
        for keep in [
            "http://sig-store:8080/refund-candidates?limit=500",
            "http://sig-store:8080/submissions?pending=claims&chain_id_to=7565164",
            // A submissionId in a path is data, not a credential.
            "http://sig-store:8080/submissions/0x38192d13e1e86923c5b497bdc3ca137643ad5112fef39e7f39bcfcdccfce6729",
        ] {
            assert_eq!(scrub(keep), keep, "should be left alone");
        }
        for hide in [
            "https://eth-sepolia.rpc.example/v2/alch_Ex4mpl3K3y-N0t-Re4l7",
            "https://rpc.test/9f2b41c7d8e05a6390bb",
        ] {
            assert!(matches!(scrub(hide), Cow::Owned(_)), "should be redacted: {hide}");
        }
    }

    #[test]
    fn the_writer_scrubs_across_split_writes_and_on_drop() {
        let sink = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        struct Shared(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl Write for Shared {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        {
            let mut w = ScrubWriter::new(Shared(sink.clone()));
            // The URL is split mid-key across two writes: a naive per-write
            // scrub would miss it.
            w.write_all(b"url (https://eth-sepolia.rpc.example/v2/alch_Ex4m").unwrap();
            w.write_all(b"pl3K3y-N0t-Re4l7)\n").unwrap();
            // No trailing newline: flushed by Drop.
            w.write_all(b"tail https://c.test/v2/alch_Ex4mpl3K3y-N0t-Re4l7").unwrap();
        }
        let out = String::from_utf8(sink.lock().unwrap().clone()).unwrap();
        assert!(!out.contains("alch_Ex4m"), "{out}");
        assert_eq!(out.lines().count(), 2, "{out}");
        assert!(out.ends_with("tail https://c.test/v2/<redacted>"), "{out}");
    }
}
