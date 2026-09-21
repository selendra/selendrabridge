//! Filter for logs that were written BEFORE the scrubbing writer existed:
//!
//! ```text
//! docker logs testnet-mesh9-validator-val-1-1 2>&1 | cargo run -p log-scrub --example scrub-stdin
//! ```
//!
//! Same code path as the live writer, so it is also how you check what the
//! writer would do to a line without restarting anything.

use std::io::{self, BufRead, Write};

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line?;
        writeln!(out, "{}", log_scrub::scrub(&line))?;
    }
    out.flush()
}
