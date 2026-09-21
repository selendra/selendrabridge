//! The GraphQL schema: a read view over the signature store plus a single
//! `submitSignature` mutation that goes through the same trust-boundary `upsert`.
//!
//! Nothing here talks to a chain — it reports what the validators have *signed*,
//! not what the keeper has executed on-chain. `meetsThreshold` therefore means
//! "has enough signatures for the keeper to claim", given the `--threshold` the
//! API was started with (omitted => `meetsThreshold` is null).

use std::sync::Arc;

use async_graphql::{ComplexObject, Context, Enum, InputObject, Object, SimpleObject};
use bridge_core::allow::{SubmissionHistory, SwapBridgeInfo, SwapRecord};
use bridge_core::backend::StoreBackend;
use bridge_core::store::{SignerSig, SubmissionRecord};

use crate::chain::{ChainInfo, Chains, GateScale};
use crate::swap::{PoolInfo, PoolToken, Swaps};

/// Rows returned by a list query when the caller passes no `limit`.
pub const DEFAULT_PAGE: u64 = 50;
/// Hard ceiling on rows per list query, whatever `limit` says. Bounds the
/// per-row `eth_call` fan-out of `executed`/`cancelled`/`status` (M-8) together
/// with the `complexity` multipliers below.
pub const MAX_PAGE: u64 = 200;
/// Complexity charged for one field that costs an upstream RPC call
/// (`executed`, `cancelled`, `status`). With the list multipliers this is what
/// makes `limit_complexity` a bound on RPC fan-out rather than on JSON size.
pub const CHAIN_READ_COST: usize = 20;

/// Complexity charged for a field that pulls a page from the signature store —
/// one HTTP round trip returning up to the store's own 5,000-row page.
///
/// Audit 2026-09-16, H-7: these fields used to cost the default 1, so ~4,000
/// aliases of `stats` fitted one 128 KiB body and async-graphql resolved them
/// CONCURRENTLY. The list multiplier also *replaced* the field's own cost, which
/// made `submissions(limit: 1)` score 1 while still fetching the full page — so
/// the formulas below are additive: the fetch is paid for whatever the page size.
pub const STORE_READ_COST: usize = 50;

/// Complexity for a whole-pool snapshot: a block number, the stable address and
/// two `eth_call`s per listed token, so it is worth several plain chain reads.
pub const POOL_READ_COST: usize = CHAIN_READ_COST * 8;

/// Effective page size for a `limit` argument: default when absent, capped at
/// [`MAX_PAGE`], never zero.
pub fn page_size(limit: Option<u64>) -> usize {
    limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE) as usize
}

/// The `limit`/`offset` window over an already-loaded list.
///
/// The page is cut HERE, after the resolver's own filters, rather than asked of
/// the store. The sig-store now takes `limit`/`offset` on `GET /submissions` and
/// `GET /history` (`RemoteStore::load_page` / `history_page`, server default and
/// cap 5,000 rows) — but those routes take no `chain_id_from`/`chain_id_to`/
/// `stuck` filters, so a server-side window under a client-side filter would
/// return short, misaligned pages. Until the store filters too, the store's cap
/// bounds the load and this bounds the response; the finding's point — per-row
/// chain reads happen only for the rows RETURNED — holds either way, and the
/// wire shape will not change when the cut moves server-side.
pub fn paginate<T>(rows: Vec<T>, limit: Option<u64>, offset: Option<u64>) -> Vec<T> {
    let skip = offset.unwrap_or(0) as usize;
    rows.into_iter().skip(skip).take(page_size(limit)).collect()
}

/// Turn a store/backend failure into a client-facing GraphQL error.
///
/// `RemoteError`'s `Display` is reqwest's, and reqwest prints the request URL —
/// i.e. the sig-store's internal address (and, in a misconfigured deployment,
/// anything in its userinfo). That went straight into the `errors[]` of the one
/// service that faces the internet. The detail is logged here; the client gets
/// a fixed message. Store-side rejections (`StoreError`: bad id, signature
/// mismatch, ...) carry no URL and are still passed through — the caller needs
/// them to fix its input.
pub fn store_error(e: anyhow::Error) -> async_graphql::Error {
    if e.downcast_ref::<bridge_core::remote::RemoteError>().is_some()
        || e.downcast_ref::<reqwest::Error>().is_some()
    {
        tracing::warn!(error = ?e, "signature store request failed");
        return async_graphql::Error::new("signature store unavailable");
    }
    async_graphql::Error::new(e.to_string())
}

/// Shared, read-mostly state handed to every resolver via the schema's data.
pub struct ApiState {
    pub backend: Arc<StoreBackend>,
    /// Signature count the keeper requires to claim. `None` => unknown here, so
    /// `meetsThreshold`/`ready` are reported as null/zero.
    pub threshold: Option<u64>,
    /// Optional destination-gate RPCs, so `executed`/`status` can report on-chain
    /// delivery. Empty => those fields are null/UNKNOWN.
    pub chains: Chains,
    /// The network registry served to the UI via the `chains` query (so the
    /// frontend discovers configured chains instead of hardcoding them). Empty
    /// when the API wasn't started with `--chains-file`.
    pub registry: Vec<ChainInfo>,
    /// Optional same-chain `SwapPool` RPCs, so `pools`/`swapQuote` can report
    /// live pool state. Empty => those fields are null.
    pub swaps: Swaps,
    // NOTE: there is deliberately no database handle here. `history` and
    // `swapHistory` read the indexer's data through the sig-store's `Read`
    // scope, on the same read-only bearer token this service already carries.
    // A Postgres credential in THIS process — the only one published to the
    // internet — would sit outside `bridge_core::auth` entirely and could write
    // signatures, rewrite the allowlists, and forge the `refund_status` the
    // sig-store refuses to expose at any scope.
}

/// A network the bridge UI can target. Mirrors [`ChainInfo`] for the wire.
#[derive(SimpleObject)]
pub struct Chain {
    pub chain_id: u64,
    pub name: String,
    /// Browser-safe, KEYLESS read-only RPC for off-wallet reads
    /// (decimals/balances) — the registry's `public_rpc_url`. Null when the
    /// operator has not published one; the UI then reads through the wallet.
    /// The server-side `rpc_url` (which may carry a provider key) is never
    /// returned here.
    pub rpc_url: Option<String>,
    /// Deployed Gate on this chain, or null if it isn't pinned server-side.
    pub gate: Option<String>,
    /// Default ERC-20 to prefill when bridging from this chain. Null if unset.
    pub token: Option<String>,
    /// All ERC-20s that can be bridged from this chain (for the UI's token
    /// picker). Empty when the registry doesn't list any.
    pub tokens: Vec<Token>,
    /// Deployed `SwapRouter` on this chain, for cross-chain-swap. Null if unset.
    pub router: Option<String>,
}

/// One bridgeable token on a chain.
#[derive(SimpleObject)]
#[graphql(complex)]
pub struct Token {
    pub symbol: String,
    /// `0x`-prefixed ERC-20 address on this chain.
    pub address: String,
    #[graphql(skip)]
    pub chain_id: u64,
    /// The registry's figure, served only through [`Token::bridge_decimals`].
    #[graphql(skip)]
    pub listed_bridge_decimals: Option<u8>,
}

#[ComplexObject]
impl Token {
    /// The decimals transfer amounts of this asset are expressed in (the
    /// `amount` of a submission or history row), NOT this token's own decimals.
    /// Null when the registry does not say, or when this chain's gate is
    /// registered at a different scale than the registry claims.
    ///
    /// Only an EVM token has one gate registration to check against. A Solana
    /// mint does not: the program keys its asset records by the PEER corridor's
    /// debridgeId, so one mint has a scale per corridor and none of its own.
    /// Its registry figure is served as before rather than blanked — parsing
    /// the base58 mint as an EVM address and giving up made every Solana
    /// token `null` (caught replaying live mesh8, 2026-09-17).
    async fn bridge_decimals(&self, ctx: &Context<'_>) -> Option<u8> {
        let listed = self.listed_bridge_decimals?;
        match self.address.parse::<alloy_primitives::Address>() {
            Ok(token) => state(ctx).verified_bridge_decimals(self.chain_id, token, listed).await,
            Err(_) => Some(listed),
        }
    }
}

impl From<ChainInfo> for Chain {
    fn from(c: ChainInfo) -> Self {
        Chain {
            chain_id: c.chain_id,
            name: c.name,
            // H-4: only the public endpoint ever crosses the wire.
            rpc_url: c.public_rpc_url,
            gate: c.gate,
            token: c.token,
            tokens: c
                .tokens
                .into_iter()
                .map(|t| Token {
                    symbol: t.symbol,
                    address: t.address,
                    chain_id: c.chain_id,
                    listed_bridge_decimals: t.bridge_decimals,
                })
                .collect(),
            router: c.router,
        }
    }
}

/// One listed token in a same-chain swap pool. Numeric fields are decimal
/// strings (uint256) to avoid JSON precision loss, like `Submission.amount`.
#[derive(SimpleObject)]
pub struct PoolTokenView {
    /// `0x`-prefixed token address (base58 mint on Solana).
    pub token: String,
    /// The pool's vault for this token — Solana only, `null` on EVM where the
    /// pool contract holds its own balances. A UI needs it to build the swap
    /// instruction; a wrong one fails the transaction rather than misdirecting
    /// it, since the program pins the vault in its own token record.
    pub vault: Option<String>,
    /// ERC-20 symbol (empty if the token doesn't expose one).
    pub symbol: String,
    pub decimals: u8,
    /// USD price, 1e18-scaled, decimal string.
    pub price: String,
    /// Current reserve (the swap lock), in token base units, decimal string.
    pub reserve: String,
    /// Max swap-out value in 1e18-scaled USD (`reserve*price/10^decimals`).
    pub max_swap_usd: String,
    /// True for the pool's core-price stablecoin.
    pub is_stable: bool,
    /// Unix seconds the current price was set (Solana only; null on EVM).
    /// `0` means never stamped, which the program treats as stale.
    pub price_set_at: Option<i64>,
    /// Whether the program would accept this price now (Solana only; null on
    /// EVM). `false` means a swap through this token reverts `StalePrice` and
    /// `swapQuote` returns null for it.
    pub price_fresh: Option<bool>,
}

/// What a browser needs to build a Solana gate `send`. See the resolver for why
/// none of it is trusted with the destination of the transfer.
#[derive(SimpleObject)]
pub struct SolanaGateContext {
    /// Base58 gate program id.
    pub program_id: String,
    /// `0x` + 64 hex — the deployment generation, hashed into the submissionId.
    pub bridge_domain: String,
    /// The gate's own chain id (deBridge's id for Solana).
    pub chain_id: u64,
    /// Next nonce for this destination corridor.
    pub nonce: u64,
    pub debridge_id: String,
    /// The registered vault the tokens are locked into.
    pub vault: String,
    /// The mint's decimals, for amount entry.
    pub decimals: u8,
    /// The asset's bridge decimals: the entered amount must be a whole multiple
    /// of `10^(decimals - bridgeDecimals)`, and the submissionId hashes the amount
    /// divided by that.
    pub bridge_decimals: u8,
    /// True when the gate's circuit breaker is tripped — a `send` would revert.
    pub paused: bool,
}

/// A configured same-chain swap pool: its contract address, core stablecoin,
/// and the tokens listed on it. The `address` is what a wallet sends
/// `approve`/`swap` to, so a UI can execute a swap end-to-end from this alone.
#[derive(SimpleObject)]
pub struct SwapPoolInfo {
    pub chain_id: u64,
    /// `0x`-prefixed SwapPool contract address.
    pub address: String,
    /// `0x`-prefixed core stablecoin (unit of account).
    pub stable: String,
    pub tokens: Vec<PoolTokenView>,
    /// Max age (seconds) of a token price the program will still swap at —
    /// the effective `max_price_age`. Solana only; null on EVM.
    pub max_price_age: Option<i64>,
}

impl SwapPoolInfo {
    fn build(chain_id: u64, info: PoolInfo) -> Self {
        SwapPoolInfo {
            chain_id,
            address: info.address,
            stable: info.stable,
            tokens: info.tokens.into_iter().map(Into::into).collect(),
            max_price_age: info.max_price_age,
        }
    }
}

impl From<PoolToken> for PoolTokenView {
    fn from(p: PoolToken) -> Self {
        PoolTokenView {
            vault: p.vault,
            token: p.token,
            symbol: p.symbol,
            decimals: p.decimals,
            price: p.price,
            reserve: p.reserve,
            max_swap_usd: p.max_swap_usd,
            is_stable: p.is_stable,
            price_set_at: p.price_set_at,
            price_fresh: p.price_fresh,
        }
    }
}

/// Lifecycle of a transfer, combining off-chain signatures with on-chain truth.
#[derive(Enum, Copy, Clone, Eq, PartialEq, Debug)]
pub enum SubmissionStatus {
    /// Fewer than `threshold` signatures collected — the keeper can't claim yet.
    Pending,
    /// Enough signatures to claim, but not yet executed on the destination chain.
    Ready,
    /// `executed(submissionId) == true` on the destination gate — delivered.
    Executed,
    /// Burned on the destination by `Gate.cancel` so the source could refund it.
    /// Also sets `executed`, hence the separate state: the funds went BACK, they
    /// did not arrive.
    Cancelled,
    /// Can't be determined (no `--threshold` and/or no destination RPC configured).
    Unknown,
}

/// One validator's signature over a submissionId.
#[derive(SimpleObject)]
pub struct Signature {
    /// Recovered signer address, `0x`-prefixed.
    pub signer: String,
    /// 65-byte ECDSA signature (r||s||v), `0x`-prefixed.
    pub signature: String,
}

impl From<SignerSig> for Signature {
    fn from(s: SignerSig) -> Self {
        Signature { signer: s.signer, signature: s.signature }
    }
}

/// A cross-chain transfer and the signatures collected for it so far.
///
/// The plain fields come straight from the store (cheap). `executed` and `status`
/// are resolved lazily — they only hit the destination chain when a client asks
/// for them, and only if the API was started with a `--gate` for `chainIdTo`.
#[derive(SimpleObject)]
#[graphql(complex)]
pub struct Submission {
    /// The sacred submissionId (`0x`-prefixed keccak of the transfer params).
    pub submission_id: String,
    pub debridge_id: String,
    /// uint256 as a decimal string (avoids JSON precision loss).
    pub amount: String,
    pub chain_id_from: u64,
    pub chain_id_to: u64,
    pub nonce: u64,
    /// `0x`-prefixed raw receiver bytes.
    pub receiver: String,
    /// `0x`-prefixed execution payload (`0x` when none).
    pub auto_params: String,
    /// `0x`-prefixed packed source sender.
    pub native_sender: String,
    /// The source-chain ERC-20 that was locked (empty on rows predating the
    /// refund path). Needed to build `Gate.refund`.
    pub token: String,
    pub signatures: Vec<Signature>,
    /// Convenience: `signatures.len()`.
    pub signature_count: u64,
    /// `signatureCount >= threshold`, or null if the API has no threshold set.
    pub meets_threshold: Option<bool>,
    /// Validators attesting the DESTINATION burn (`Gate.cancel`). A separate
    /// quorum from `signatures` — a transfer signature can never count here.
    pub cancel_signature_count: u64,
    /// Validators attesting the SOURCE payout (`Gate.refund`). Only forms after
    /// the burn is observed on-chain.
    pub refund_signature_count: u64,
}

impl Submission {
    fn from_record(rec: SubmissionRecord, threshold: Option<u64>) -> Self {
        let signature_count = rec.signatures.len() as u64;
        let meets_threshold = threshold.map(|t| signature_count >= t);
        Submission {
            submission_id: rec.submission_id,
            debridge_id: rec.debridge_id,
            amount: rec.amount,
            chain_id_from: rec.chain_id_from,
            chain_id_to: rec.chain_id_to,
            nonce: rec.nonce,
            receiver: rec.receiver,
            auto_params: rec.auto_params,
            native_sender: rec.native_sender,
            token: rec.token,
            cancel_signature_count: rec.cancel_signatures.len() as u64,
            refund_signature_count: rec.refund_signatures.len() as u64,
            signatures: rec.signatures.into_iter().map(Into::into).collect(),
            signature_count,
            meets_threshold,
        }
    }
}

#[ComplexObject]
impl Submission {
    /// The decimals `amount` is expressed in: the asset's bridge decimals, the
    /// same on every chain. Format `amount` with THIS, never with a local
    /// token's decimals — they differ by orders of magnitude, and the local
    /// figure is the one a client can always get, which is how M-11 rendered a
    /// 1,000-token transfer as `0`.
    ///
    /// Resolved from the registry, else from the source gate's
    /// `bridgeDecimalsOf(token)`; see [`ApiState::amount_scale`]. Null when
    /// neither can answer — then `amount` is raw units of an unknown scale and
    /// must be shown as such.
    #[graphql(complexity = "CHAIN_READ_COST")]
    async fn bridge_decimals(&self, ctx: &Context<'_>) -> Option<u8> {
        state(ctx).amount_scale(&self.debridge_id, self.chain_id_from, &self.token).await
    }

    /// On-chain `executed(submissionId)` on the destination gate. `null` when the
    /// API has no `--gate` configured for `chainIdTo` (or the RPC call failed).
    #[graphql(complexity = "CHAIN_READ_COST")]
    async fn executed(&self, ctx: &Context<'_>) -> Option<bool> {
        state(ctx).chains.executed(self.chain_id_to, &self.submission_id).await
    }

    /// On-chain `cancelled(submissionId)`: the transfer was burned on the
    /// destination so it could be refunded on the source, rather than delivered.
    #[graphql(complexity = "CHAIN_READ_COST")]
    async fn cancelled(&self, ctx: &Context<'_>) -> Option<bool> {
        state(ctx).chains.cancelled(self.chain_id_to, &self.submission_id).await
    }

    /// Combined lifecycle: CANCELLED if the destination burned it, EXECUTED if
    /// the destination gate confirms delivery, otherwise READY/PENDING from the
    /// signature count, or UNKNOWN if neither a threshold nor a destination RPC
    /// is configured.
    #[graphql(complexity = "CHAIN_READ_COST")]
    async fn status(&self, ctx: &Context<'_>) -> SubmissionStatus {
        let chains = &state(ctx).chains;
        if chains.executed(self.chain_id_to, &self.submission_id).await == Some(true) {
            // `cancel` sets `executed` too, so check which one it was before
            // telling anyone their funds were delivered.
            if chains.cancelled(self.chain_id_to, &self.submission_id).await == Some(true) {
                return SubmissionStatus::Cancelled;
            }
            return SubmissionStatus::Executed;
        }
        match self.meets_threshold {
            Some(true) => SubmissionStatus::Ready,
            Some(false) => SubmissionStatus::Pending,
            None => SubmissionStatus::Unknown,
        }
    }
}

/// Optional filters for `submissions`. All supplied fields must match (AND).
#[derive(InputObject, Default)]
pub struct SubmissionFilter {
    pub chain_id_from: Option<u64>,
    pub chain_id_to: Option<u64>,
    /// Keep only records with at least this many signatures.
    pub min_signatures: Option<u64>,
    /// `true` => only records that meet the keeper threshold; `false` => only
    /// those that don't. Requires the API to have been started with `--threshold`.
    pub ready: Option<bool>,
}

/// How many submissions flow along one source→destination route.
#[derive(SimpleObject)]
pub struct RouteCount {
    pub chain_id_from: u64,
    pub chain_id_to: u64,
    pub count: u64,
}

/// Aggregate view of the whole store.
#[derive(SimpleObject)]
pub struct Stats {
    /// Total records in the store.
    pub total: u64,
    /// Records with at least one signature.
    pub signed: u64,
    /// Records that meet the threshold (0 if no threshold is configured).
    pub ready: u64,
    /// The configured keeper threshold, if any.
    pub threshold: Option<u64>,
    /// Per source→destination route counts, sorted by (from, to).
    pub routes: Vec<RouteCount>,
}

/// `symbol` is a query ARGUMENT — any anonymous caller's string. Formatted with
/// `Display` (`%symbol`) it reached the log verbatim, so a `\n` in it forged a
/// whole log line of the caller's choosing (audit 2026-09-16, LOW). `Debug`
/// quotes it and escapes every control character.
fn warn_unmapped_symbol(chain_id: u64, chain_id_to: u64, symbol: &str) {
    tracing::warn!(chain_id, chain_id_to, symbol = ?symbol, "no debridgeId mapped on both solana gate and destination");
}

fn state<'c>(ctx: &Context<'c>) -> &'c ApiState {
    ctx.data_unchecked::<ApiState>()
}

impl ApiState {
    /// The bridge decimals a transfer's `amount` is denominated in, resolved
    /// from its `debridgeId` — `keccak(chainId, token)` of an EVM asset in the
    /// registry. A Solana-origin transfer carries such a (peer) id too, so this
    /// covers both VMs. `None` when no registry token derives that id.
    ///
    /// The registry is an operator-edited file; the gate is what actually
    /// scales the transfer. So the registry's figure is served only once the
    /// token's own gate agrees with it — see [`served_bridge_decimals`].
    pub async fn bridge_decimals_of(&self, debridge_id: &str) -> Option<u8> {
        let want = debridge_id.trim().to_ascii_lowercase();
        let (chain_id, token, listed) = self.registry.iter().find_map(|c| {
            c.tokens.iter().find_map(|t| {
                let dec = t.bridge_decimals?;
                let addr: alloy_primitives::Address = t.address.parse().ok()?;
                let id = bridge_core::debridge_id(alloy_primitives::U256::from(c.chain_id), addr);
                (format!("{id:#x}") == want).then_some((c.chain_id, addr, dec))
            })
        })?;
        self.verified_bridge_decimals(chain_id, token, listed).await
    }

    /// The scale one transfer's `amount` is in, for a record that also knows
    /// which token it locked on which chain.
    ///
    /// The registry lookup above answers for an asset the operator listed with
    /// `bridge_decimals`. When it cannot (M-11: `scripts/run.sh` never emits the
    /// field, and the tracked `docker/configs/chains.json` omits it, so on those
    /// stacks EVERY row came back null), this asks the source gate the same
    /// question `Gate.send` asked when it produced the amount:
    /// `bridgeDecimalsOf(token)` on `chainIdFrom`. That is the authoritative
    /// answer — the registry is an operator-edited file, the gate is what did
    /// the conversion — so it is also allowed to answer on its own.
    ///
    /// Still `None` when the row predates the refund path (empty `token`), the
    /// source is Solana (no EVM gate to ask), or no `--gate` is configured for
    /// the source chain. A client MUST then treat `amount` as raw units rather
    /// than formatting it with some local token's decimals.
    pub async fn amount_scale(&self, debridge_id: &str, chain_id_from: u64, token: &str) -> Option<u8> {
        if let Some(d) = self.bridge_decimals_of(debridge_id).await {
            return Some(d);
        }
        let token: alloy_primitives::Address = token.trim().parse().ok()?;
        match self.chains.gate_bridge_decimals(chain_id_from, token).await {
            GateScale::Registered(d) => Some(d),
            GateScale::Unregistered | GateScale::Unknown => None,
        }
    }

    /// The registry's `listed` bridge decimals for `token` on `chain_id`, checked
    /// against that chain's gate. See [`served_bridge_decimals`].
    async fn verified_bridge_decimals(&self, chain_id: u64, token: alloy_primitives::Address, listed: u8) -> Option<u8> {
        let on_chain = self.chains.gate_bridge_decimals(chain_id, token).await;
        let served = served_bridge_decimals(listed, on_chain);
        if served.is_none() && self.chains.first_scale_warning(chain_id, token) {
            tracing::warn!(
                chain_id, %token, registry = listed, gate = ?on_chain,
                "registry bridge_decimals disagrees with the gate; serving bridgeDecimals: null"
            );
        }
        served
    }
}

/// What to serve as `bridgeDecimals` given the registry's figure and the gate's.
///
/// Audit 2026-09-16 (LOW): the registry's value was served unchecked. A typo in
/// it misformats every amount of that asset by a power of ten in the explorer —
/// the same class of error H-2 guards the signers against — with nothing to say
/// the page is wrong. A disagreement is now `null`, which a client already has
/// to handle (and which the frontend renders with its own fallback rather than
/// a confidently wrong number).
///
/// A gate that cannot be asked right now (`Unknown`) is not a disagreement:
/// the registry's figure stands, as it did before, rather than blanking every
/// amount over one slow RPC. It is not remembered, so the next request checks.
pub fn served_bridge_decimals(registry: u8, gate: GateScale) -> Option<u8> {
    match gate {
        GateScale::Registered(d) => (d == registry).then_some(d),
        GateScale::Unregistered => None,
        GateScale::Unknown => Some(registry),
    }
}



/// The swap intent (and destination outcome, once known) of a
/// `SwapRouter.swapAndBridge` transfer — a plain bridge send has none.
///
/// ## Every amount here is in a DIFFERENT scale (M-12)
///
/// The three figures below are LOCAL amounts of three different tokens on two
/// chains, and they sit beside a `HistoryEntry.amount` that is a WIRE amount.
/// One `bridgeDecimals` label used to be the only scale declared on the object,
/// so a client had no way to render the rest except by guessing. Each now
/// carries its own `…Decimals` field, resolved from the token it belongs to:
///
/// | field | token | chain |
/// |---|---|---|
/// | `amountIn` | `tokenIn` | source |
/// | `stableOut` | the pool's stable (what the gate locked) | source |
/// | `finalizeAmountOut` | `finalToken`, or the stable on a fallback | destination |
/// | (`HistoryEntry.amount`) | bridge decimals, not local | — |
#[derive(SimpleObject)]
#[graphql(complex)]
pub struct SwapIntent {
    pub token_in: String,
    /// LOCAL amount of `tokenIn` the user put in — see `amountInDecimals`.
    pub amount_in: String,
    /// LOCAL amount of the source chain's stable the swap produced, which is
    /// what `Gate.send` then locked — see `stableOutDecimals`. NOT the wire
    /// amount: the gate converts it, and `HistoryEntry.amount` is the result.
    pub stable_out: String,
    pub final_token: String,
    pub final_receiver: String,
    /// Destination-chain finalize tx, once the swap-back leg has run.
    pub finalize_tx: Option<String>,
    /// LOCAL amount delivered on the destination — see
    /// `finalizeAmountOutDecimals`, whose token depends on `finalizeFallback`.
    pub finalize_amount_out: Option<String>,
    /// True if the destination swap failed and the stable was delivered as-is.
    pub finalize_fallback: Option<bool>,
    pub finalized_at: Option<String>,
    /// Source chain, for resolving the scales above. Not part of the schema —
    /// the enclosing row already says it.
    #[graphql(skip)]
    pub chain_id_from: u64,
    /// Destination chain, likewise.
    #[graphql(skip)]
    pub chain_id_to: u64,
    /// The source ERC-20 the gate locked (the pool's stable), from the
    /// enclosing row's `token`.
    #[graphql(skip)]
    pub locked_token: Option<String>,
    /// The corridor id, for naming the destination's local token on a fallback.
    #[graphql(skip)]
    pub debridge_id: String,
}

#[ComplexObject]
impl SwapIntent {
    /// Decimals of `tokenIn` on the source chain. Null when it cannot be read
    /// (no `--gate` for that chain, or the address is not an ERC-20).
    #[graphql(complexity = "CHAIN_READ_COST")]
    async fn amount_in_decimals(&self, ctx: &Context<'_>) -> Option<u8> {
        let token = self.token_in.trim().parse().ok()?;
        state(ctx).chains.token_decimals(self.chain_id_from, token).await
    }

    /// Decimals of the stable `stableOut` is denominated in, on the source
    /// chain — the token the gate locked.
    #[graphql(complexity = "CHAIN_READ_COST")]
    async fn stable_out_decimals(&self, ctx: &Context<'_>) -> Option<u8> {
        let token = self.locked_token.as_deref()?.trim().parse().ok()?;
        state(ctx).chains.token_decimals(self.chain_id_from, token).await
    }

    /// Decimals `finalizeAmountOut` is in, on the DESTINATION chain.
    ///
    /// Which token that is depends on how the delivery went: normally
    /// `finalToken`, but on `finalizeFallback` the destination swap failed and
    /// the bridged stable was paid out instead — a different token, usually a
    /// different scale. Null before the transfer finalises, or when the token
    /// cannot be read.
    #[graphql(complexity = "CHAIN_READ_COST")]
    async fn finalize_amount_out_decimals(&self, ctx: &Context<'_>) -> Option<u8> {
        self.finalize_amount_out.as_ref()?;
        let st = state(ctx);
        if self.finalize_fallback == Some(true) {
            // The stable that arrived is the destination gate's local token for
            // this corridor — what it paid the claim out in.
            let id: alloy_primitives::B256 = self.debridge_id.trim().parse().ok()?;
            return st.chains.local_token_decimals(self.chain_id_to, id).await;
        }
        let token = self.final_token.trim().parse().ok()?;
        st.chains.token_decimals(self.chain_id_to, token).await
    }
}

impl SwapIntent {
    /// `i` carries only what the router's event recorded; the scales need the
    /// enclosing row's chains, locked token and corridor id.
    fn from_info(
        i: SwapBridgeInfo,
        chain_id_from: u64,
        chain_id_to: u64,
        locked_token: Option<String>,
        debridge_id: String,
    ) -> Self {
        SwapIntent {
            token_in: i.token_in,
            amount_in: i.amount_in,
            stable_out: i.stable_out,
            final_token: i.final_token,
            final_receiver: i.final_receiver,
            finalize_tx: i.finalize_tx,
            finalize_amount_out: i.finalize_amount_out,
            finalize_fallback: i.finalize_fallback,
            finalized_at: i.finalized_at,
            chain_id_from,
            chain_id_to,
            locked_token,
            debridge_id,
        }
    }
}

/// One row of the database-backed transaction-history view: every bridge
/// transfer the `indexer` has observed, regardless of whether it ever got a
/// validator signature — unlike `submissions`/`submission` (signature-store
/// view), this is where a stuck/failed transfer is visible.
#[derive(SimpleObject)]
#[graphql(complex)]
pub struct HistoryEntry {
    pub submission_id: String,
    pub debridge_id: String,
    pub amount: String,
    pub chain_id_from: u64,
    pub chain_id_to: u64,
    pub nonce: u64,
    pub receiver: String,
    pub status: String,
    pub claim_tx: Option<String>,
    pub signature_count: u64,
    pub created_at: String,
    pub updated_at: String,
    /// True once this transfer has entered the refund lifecycle at all.
    pub stuck: bool,
    /// `none` | `eligible` | `cancelled` | `refunded`. `cancelled` means the
    /// destination was burned so the source could repay; `refunded` means the
    /// funds are back with the sender.
    pub refund_status: String,
    /// Source-chain `Gate.refund` tx hash.
    pub refund_tx: Option<String>,
    /// Destination-chain `Gate.cancel` tx hash.
    pub cancel_tx: Option<String>,
    /// The source-chain ERC-20 that was locked.
    pub token: Option<String>,
    /// Validators attesting the destination burn.
    pub cancel_signature_count: u64,
    /// Validators attesting the source payout.
    pub refund_signature_count: u64,
    /// Set when this transfer originated from `SwapRouter.swapAndBridge`.
    pub swap_intent: Option<SwapIntent>,
}

#[ComplexObject]
impl HistoryEntry {
    /// The decimals `amount` is expressed in — see `Submission.bridgeDecimals`.
    #[graphql(complexity = "CHAIN_READ_COST")]
    async fn bridge_decimals(&self, ctx: &Context<'_>) -> Option<u8> {
        state(ctx)
            .amount_scale(&self.debridge_id, self.chain_id_from, self.token.as_deref().unwrap_or_default())
            .await
    }
}

impl From<SubmissionHistory> for HistoryEntry {
    fn from(h: SubmissionHistory) -> Self {
        // The intent's scales are per-token and per-chain, so it needs what the
        // row knows and the router's event did not record (M-12).
        let swap_intent = h.swap_intent.map(|i| {
            SwapIntent::from_info(i, h.chain_id_from, h.chain_id_to, h.token.clone(), h.debridge_id.clone())
        });
        HistoryEntry {
            submission_id: h.submission_id,
            debridge_id: h.debridge_id,
            amount: h.amount,
            chain_id_from: h.chain_id_from,
            chain_id_to: h.chain_id_to,
            nonce: h.nonce,
            receiver: h.receiver,
            status: h.status,
            claim_tx: h.claim_tx,
            signature_count: h.signature_count as u64,
            created_at: h.created_at,
            updated_at: h.updated_at,
            stuck: h.stuck,
            refund_status: h.refund_status,
            refund_tx: h.refund_tx,
            cancel_tx: h.cancel_tx,
            token: h.token,
            cancel_signature_count: h.cancel_signature_count as u64,
            refund_signature_count: h.refund_signature_count as u64,
            swap_intent,
        }
    }
}

/// Optional filters for `history`. All supplied fields must match (AND).
#[derive(InputObject, Default)]
pub struct HistoryFilter {
    pub chain_id_from: Option<u64>,
    pub chain_id_to: Option<u64>,
    /// Keep only transfers flagged stuck (refund-eligible).
    pub stuck_only: Option<bool>,
    /// Exact-match one submissionId (e.g. to look up refund/stuck status for a
    /// detail view already loaded via `submission`). Case-insensitive.
    pub submission_id: Option<String>,
}

/// One completed same-chain swap (`SwapPool.Swapped`), mirrored by the indexer.
///
/// `amountIn` and `amountOut` are LOCAL amounts of TWO DIFFERENT tokens — that
/// is what a swap is. Neither is in "the chain's decimals": a pool trading an
/// 18-decimal alt for a 6-decimal stable produces two figures that share a row
/// and nothing else. Each declares its own scale below (same class as M-11: the
/// right kind of units, read off the wrong token).
#[derive(SimpleObject)]
#[graphql(complex)]
pub struct SwapHistoryEntry {
    pub chain_id: u64,
    pub tx_hash: String,
    pub sender: String,
    pub receiver: String,
    pub token_in: String,
    pub token_out: String,
    pub amount_in: String,
    pub amount_out: String,
    pub block_number: u64,
    pub created_at: String,
}

#[ComplexObject]
impl SwapHistoryEntry {
    /// Decimals of `tokenIn` on this chain — the scale `amountIn` is in.
    /// Null when the token cannot be read (no `--gate` for the chain, or it is
    /// not an ERC-20); a client must then show the raw integer.
    #[graphql(complexity = "CHAIN_READ_COST")]
    async fn amount_in_decimals(&self, ctx: &Context<'_>) -> Option<u8> {
        let token = self.token_in.trim().parse().ok()?;
        state(ctx).chains.token_decimals(self.chain_id, token).await
    }

    /// Decimals of `tokenOut` on this chain — the scale `amountOut` is in, and
    /// in general NOT the same as `amountInDecimals`.
    #[graphql(complexity = "CHAIN_READ_COST")]
    async fn amount_out_decimals(&self, ctx: &Context<'_>) -> Option<u8> {
        let token = self.token_out.trim().parse().ok()?;
        state(ctx).chains.token_decimals(self.chain_id, token).await
    }
}

impl From<SwapRecord> for SwapHistoryEntry {
    fn from(s: SwapRecord) -> Self {
        SwapHistoryEntry {
            chain_id: s.chain_id,
            tx_hash: s.tx_hash,
            sender: s.sender,
            receiver: s.receiver,
            token_in: s.token_in,
            token_out: s.token_out,
            amount_in: s.amount_in,
            amount_out: s.amount_out,
            block_number: s.block_number,
            created_at: s.created_at,
        }
    }
}

pub struct Query;

#[Object]
impl Query {
    /// Submissions matching `filter`, sorted by (chainIdFrom, chainIdTo, nonce)
    /// for a stable order, as one page: `limit` rows (default 50, at most 200)
    /// starting at `offset` (default 0). Both are optional, so existing clients
    /// keep working and simply receive the first page.
    #[graphql(complexity = "STORE_READ_COST + page_size(limit) * child_complexity")]
    async fn submissions(
        &self,
        ctx: &Context<'_>,
        filter: Option<SubmissionFilter>,
        limit: Option<u64>,
        offset: Option<u64>,
    ) -> async_graphql::Result<Vec<Submission>> {
        let st = state(ctx);
        let f = filter.unwrap_or_default();
        let threshold = st.threshold;

        let mut records = st.backend.load_all().await.map_err(store_error)?;
        records.sort_by(|a, b| {
            (a.chain_id_from, a.chain_id_to, a.nonce).cmp(&(
                b.chain_id_from,
                b.chain_id_to,
                b.nonce,
            ))
        });

        let out = records
            .into_iter()
            .filter(|r| f.chain_id_from.is_none_or(|c| r.chain_id_from == c))
            .filter(|r| f.chain_id_to.is_none_or(|c| r.chain_id_to == c))
            .filter(|r| f.min_signatures.is_none_or(|m| r.signatures.len() as u64 >= m))
            .filter(|r| match (f.ready, threshold) {
                (Some(want), Some(t)) => (r.signatures.len() as u64 >= t) == want,
                (Some(_), None) => false, // asked to filter by readiness but we can't judge
                (None, _) => true,
            })
            .map(|r| Submission::from_record(r, threshold))
            .collect();
        Ok(paginate(out, limit, offset))
    }

    /// A single submission by its `0x`-prefixed submissionId, or null if unknown.
    #[graphql(complexity = "STORE_READ_COST")]
    async fn submission(
        &self,
        ctx: &Context<'_>,
        submission_id: String,
    ) -> async_graphql::Result<Option<Submission>> {
        // Reject anything that isn't a 32-byte hex hash before it reaches a
        // backend, where it would otherwise build a file path (dir) or a URL
        // (remote) — path-traversal / URL-injection defense at the boundary.
        if !bridge_core::store::is_valid_submission_id(&submission_id) {
            return Err(async_graphql::Error::new(
                "submissionId must be a 32-byte hex hash (0x + 64 hex digits)",
            ));
        }
        let st = state(ctx);
        let rec = st.backend.load(&submission_id).await.map_err(store_error)?;
        Ok(rec.map(|r| Submission::from_record(r, st.threshold)))
    }

    /// The configured network registry, so the UI can discover chains (id, name,
    /// RPC, gate, token) from the backend instead of hardcoding them. Empty when
    /// the API was started without `--chains-file`.
    async fn chains(&self, ctx: &Context<'_>) -> Vec<Chain> {
        state(ctx).registry.iter().cloned().map(Chain::from).collect()
    }

    /// Live snapshot of a same-chain swap pool: every listed token with its
    /// price, reserve (the swap lock), and max-swap-out USD value. `null` when
    /// the API has no `--swap` configured for `chainId` (or the RPC read failed).
    #[graphql(complexity = "POOL_READ_COST")]
    async fn pools(&self, ctx: &Context<'_>, chain_id: u64) -> Option<Vec<PoolTokenView>> {
        state(ctx)
            .swaps
            .pools(chain_id)
            .await
            .map(|v| v.into_iter().map(Into::into).collect())
    }

    /// Full snapshot of a same-chain swap pool INCLUDING its contract address and
    /// core stablecoin, so a UI can execute a swap (approve + `swap`) against it.
    /// `null` when the API has no `--swap` for `chainId` (or the RPC read failed).
    #[graphql(complexity = "POOL_READ_COST")]
    async fn swap_pool(&self, ctx: &Context<'_>, chain_id: u64) -> Option<SwapPoolInfo> {
        state(ctx)
            .swaps
            .pool_info(chain_id)
            .await
            .map(|info| SwapPoolInfo::build(chain_id, info))
    }

    /// On-chain `quote` for a same-chain swap: the pegged output (net of fee,
    /// before the reserve cap) for swapping `amountIn` of `tokenIn` into
    /// `tokenOut`, as a decimal string. `null` when the chain isn't configured,
    /// an address/amount is malformed, a token isn't listed (call reverts), or —
    /// on Solana — a leg's price is older than the pool's `maxPriceAge`, which
    /// the program would reject as `StalePrice` (see `PoolTokenView.priceFresh`).
    #[graphql(complexity = "CHAIN_READ_COST")]
    async fn swap_quote(
        &self,
        ctx: &Context<'_>,
        chain_id: u64,
        token_in: String,
        token_out: String,
        amount_in: String,
    ) -> Option<String> {
        state(ctx).swaps.quote(chain_id, &token_in, &token_out, &amount_in).await
    }

    /// Everything a browser needs to build a `send` on the Solana gate for one
    /// asset and destination: the deployment domain, the corridor's next nonce,
    /// and the registered vault.
    ///
    /// None of it can redirect a transfer — the receiver, amount and destination
    /// are packed into the instruction by the browser, and a wrong value here
    /// yields a submissionId the program does not derive, so the transaction
    /// fails rather than pays the wrong account.
    #[graphql(complexity = "CHAIN_READ_COST * 4")]
    async fn solana_gate_context(
        &self,
        ctx: &Context<'_>,
        chain_id: u64,
        // `symbol` is the asset as the registry lists it; the debridgeId is
        // derived from an EVM chain's token for that symbol.
        symbol: String,
        chain_id_to: u64,
    ) -> Option<SolanaGateContext> {
        let st = state(ctx);
        let gate = st.chains.solana_gate(chain_id)?;
        // The debridgeId is DERIVED, not configured: `keccak(chainId, token)` of
        // the asset on some EVM chain that carries it. It must be registered on
        // BOTH ends — the Solana program (or `send` is refused) and the
        // destination gate (or `claim` reverts UnknownAsset, which the keeper
        // skips silently, stranding the lock until a refund).
        //
        // The destination's OWN id is the one a full-mesh deploy never maps:
        // each gate registers the ids of its PEERS' tokens, not its own. So
        // prefer peer-derived ids, keep the destination's last, and ask the
        // destination gate which it can actually pay out.
        let mut candidates: Vec<(u64, alloy_primitives::Address)> = st
            .registry
            .iter()
            .filter(|c| c.chain_id != chain_id)
            .filter_map(|c| {
                let t = c.tokens.iter().find(|t| t.symbol.eq_ignore_ascii_case(&symbol))?;
                Some((c.chain_id, t.address.parse().ok()?))
            })
            .collect();
        candidates.sort_by_key(|(cid, _)| *cid == chain_id_to);

        // An unreadable destination gate (RPC down, not configured) is not a
        // "no": fall back to the first id the Solana side accepts, which is what
        // this resolver always did.
        let mut fallback = None;
        for (cid, token) in candidates {
            let id = bridge_core::debridge_id(alloy_primitives::U256::from(cid), token);
            let Some(mapped) = st.swaps.upstream().metered(async { Some(st.chains.maps_asset(chain_id_to, id).await) }).await
            else {
                return fallback;
            };
            if mapped == Some(false) {
                continue;
            }
            let read = st.swaps.upstream().metered(async { Some(gate.send_context(&format!("{id:#x}"), chain_id_to).await) });
            let c = match read.await {
                // No slot: the upstream is saturated, so stop asking rather than
                // walk the remaining candidates into the same wall.
                None => return fallback,
                Some(Ok(c)) => c,
                Some(Err(e)) => {
                    tracing::debug!(chain_id, from_chain = cid, error = %e, "debridgeId unusable on solana gate");
                    continue;
                }
            };
            let ctx = SolanaGateContext {
                program_id: c.program_id,
                bridge_domain: c.bridge_domain,
                chain_id: c.chain_id,
                nonce: c.nonce,
                debridge_id: c.debridge_id,
                vault: c.vault,
                decimals: c.decimals,
                bridge_decimals: c.bridge_decimals,
                paused: c.paused,
            };
            if mapped == Some(true) {
                return Some(ctx);
            }
            fallback.get_or_insert(ctx);
        }
        if fallback.is_none() {
            warn_unmapped_symbol(chain_id, chain_id_to, &symbol);
        }
        fallback
    }

    /// A recent blockhash for a Solana pool's cluster. The browser builds and
    /// signs its own swap transaction — this is the one piece it cannot derive,
    /// and passing it through here keeps the RPC credential server-side.
    /// `null` for an EVM chain or an unconfigured one.
    #[graphql(complexity = "CHAIN_READ_COST")]
    async fn solana_blockhash(&self, ctx: &Context<'_>, chain_id: u64) -> Option<String> {
        state(ctx).swaps.solana_blockhash(chain_id).await
    }

    /// SPL balance of a token account, as a decimal string ("0" when the
    /// account does not exist yet). The caller derives the address; this only
    /// reads it.
    #[graphql(complexity = "CHAIN_READ_COST")]
    async fn solana_token_balance(
        &self,
        ctx: &Context<'_>,
        chain_id: u64,
        account: String,
    ) -> Option<String> {
        state(ctx).swaps.solana_token_balance(chain_id, &account).await
    }

    /// Confirmation state of a Solana transaction: `pending`, `processed`,
    /// `confirmed`, `finalized` or `failed`. `null` for an EVM chain.
    #[graphql(complexity = "CHAIN_READ_COST")]
    async fn solana_signature_status(
        &self,
        ctx: &Context<'_>,
        chain_id: u64,
        signature: String,
    ) -> Option<String> {
        state(ctx).swaps.solana_signature_status(chain_id, &signature).await
    }

    /// Aggregate counts across the whole store.
    #[graphql(complexity = "STORE_READ_COST")]
    async fn stats(&self, ctx: &Context<'_>) -> async_graphql::Result<Stats> {
        use std::collections::BTreeMap;
        let st = state(ctx);
        let records = st.backend.load_all().await.map_err(store_error)?;

        let mut signed = 0u64;
        let mut ready = 0u64;
        let mut routes: BTreeMap<(u64, u64), u64> = BTreeMap::new();
        for r in &records {
            let n = r.signatures.len() as u64;
            if n >= 1 {
                signed += 1;
            }
            if let Some(t) = st.threshold {
                if n >= t {
                    ready += 1;
                }
            }
            *routes.entry((r.chain_id_from, r.chain_id_to)).or_default() += 1;
        }

        Ok(Stats {
            total: records.len() as u64,
            signed,
            ready,
            threshold: st.threshold,
            routes: routes
                .into_iter()
                .map(|((from, to), count)| RouteCount {
                    chain_id_from: from,
                    chain_id_to: to,
                    count,
                })
                .collect(),
        })
    }

    /// Transaction history: every bridge transfer the `indexer` has observed
    /// on-chain, including ones stuck at zero signatures (which `submissions` can
    /// never show, since that view only exists once a validator has signed).
    /// Newest first.
    ///
    /// Read through the sig-store's `/history` route on this service's read-only
    /// bearer token — deliberately NOT straight from Postgres. This process is
    /// the one exposed to the internet, and a database credential here would
    /// bypass every scope in `bridge_core::auth`. Needs `--store-url`.
    ///
    /// One page: `limit` rows (default 50, at most 200) from `offset` (default
    /// 0), applied after `filter`.
    #[graphql(complexity = "STORE_READ_COST + page_size(limit) * child_complexity")]
    async fn history(
        &self,
        ctx: &Context<'_>,
        filter: Option<HistoryFilter>,
        limit: Option<u64>,
        offset: Option<u64>,
    ) -> async_graphql::Result<Vec<HistoryEntry>> {
        let f = filter.unwrap_or_default();
        let rows = state(ctx).backend.history().await.map_err(store_error)?;
        let rows: Vec<HistoryEntry> = rows
            .into_iter()
            .filter(|r| f.chain_id_from.is_none_or(|c| r.chain_id_from == c))
            .filter(|r| f.chain_id_to.is_none_or(|c| r.chain_id_to == c))
            .filter(|r| f.stuck_only.is_none_or(|want| r.stuck == want))
            .filter(|r| f.submission_id.as_deref().is_none_or(|id| r.submission_id.eq_ignore_ascii_case(id)))
            .map(Into::into)
            .collect();
        Ok(paginate(rows, limit, offset))
    }

    /// Same-chain swap history (`SwapPool.Swapped`), mirrored by the `indexer`.
    /// Newest first, optionally scoped to one chain. Served over the sig-store's
    /// read scope for the reason `history` documents. Needs `--store-url`.
    /// `limit` defaults to 50 and is capped at 200.
    #[graphql(complexity = "STORE_READ_COST + page_size(limit) * child_complexity")]
    async fn swap_history(
        &self,
        ctx: &Context<'_>,
        chain_id: Option<u64>,
        limit: Option<u64>,
    ) -> async_graphql::Result<Vec<SwapHistoryEntry>> {
        let rows = state(ctx)
            .backend
            .swaps(chain_id, page_size(limit) as u64)
            .await
            .map_err(store_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }
}

/// Mirrors a `SubmissionRecord` plus exactly one signature to merge in.
#[derive(InputObject)]
pub struct SubmissionInput {
    pub submission_id: String,
    /// Deployment generation of the gate that emitted this transfer,
    /// `0x`-prefixed bytes32. Part of the submissionId preimage, so an absent or
    /// wrong value simply fails the server-side id check — it is not a way to
    /// smuggle a record in, only a way to be rejected.
    pub bridge_domain: String,
    pub debridge_id: String,
    pub amount: String,
    pub chain_id_from: u64,
    pub chain_id_to: u64,
    pub nonce: u64,
    pub receiver: String,
    /// `0x` when there is no execution payload.
    pub auto_params: String,
    pub native_sender: String,
    /// The source-chain ERC-20 that was locked, `0x`-prefixed. Optional, but a
    /// record without it can never be refunded. Verified against `debridgeId`
    /// server-side, so it cannot be used to point a refund at another asset.
    pub token: Option<String>,
    /// The signer address for the attached signature, `0x`-prefixed.
    pub signer: String,
    /// 65-byte ECDSA signature (r||s||v), `0x`-prefixed.
    pub signature: String,
}

pub struct Mutation;

#[Object]
impl Mutation {
    /// Upsert a transfer record and merge in one validator signature. Rejected
    /// (by the same trust boundary the sig-store uses) unless the submissionId
    /// equals the keccak of the params and the signature recovers to `signer`.
    async fn submit_signature(
        &self,
        ctx: &Context<'_>,
        input: SubmissionInput,
    ) -> async_graphql::Result<Submission> {
        let st = state(ctx);
        let sig = SignerSig { signer: input.signer, signature: input.signature };
        let record = SubmissionRecord {
            submission_id: input.submission_id,
            bridge_domain: input.bridge_domain,
            debridge_id: input.debridge_id,
            amount: input.amount,
            chain_id_from: input.chain_id_from,
            chain_id_to: input.chain_id_to,
            nonce: input.nonce,
            receiver: input.receiver,
            auto_params: input.auto_params,
            native_sender: input.native_sender,
            token: input.token.unwrap_or_default(),
            signatures: Vec::new(),
            cancel_signatures: Vec::new(),
            refund_signatures: Vec::new(),
        };
        let merged = st.backend.upsert(record, sig).await.map_err(store_error)?;
        Ok(Submission::from_record(merged, st.threshold))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_size_defaults_and_caps() {
        assert_eq!(page_size(None), DEFAULT_PAGE as usize);
        assert_eq!(page_size(Some(0)), 1, "zero is not a way to ask for everything");
        assert_eq!(page_size(Some(7)), 7);
        assert_eq!(page_size(Some(u64::MAX)), MAX_PAGE as usize);
        assert_eq!(page_size(Some(MAX_PAGE + 1)), MAX_PAGE as usize);
    }

    /// M-8: with no args a caller gets the first DEFAULT_PAGE rows — never the
    /// whole table.
    #[test]
    fn paginate_windows_the_list() {
        let rows: Vec<u64> = (0..1000).collect();
        assert_eq!(paginate(rows.clone(), None, None).len(), DEFAULT_PAGE as usize);
        assert_eq!(paginate(rows.clone(), Some(10_000), None).len(), MAX_PAGE as usize);
        assert_eq!(paginate(rows.clone(), Some(3), Some(5)), vec![5, 6, 7]);
        assert!(paginate(rows.clone(), Some(3), Some(5_000)).is_empty(), "offset past the end");
        assert_eq!(paginate(rows, Some(5), Some(998)), vec![998, 999], "short last page");
    }

    /// The `chains` query must never carry the private endpoint (H-4).
    #[test]
    fn chain_view_serves_only_the_public_rpc() {
        let info = ChainInfo {
            chain_id: 1,
            name: "x".into(),
            rpc_url: Some("https://provider.example/v2/SECRETKEY".into()),
            public_rpc_url: Some("https://rpc.public.example".into()),
            gate: None,
            token: None,
            tokens: vec![],
            router: None,
            swap_pool: None,
        };
        let view = Chain::from(info.clone());
        assert_eq!(view.rpc_url.as_deref(), Some("https://rpc.public.example"));

        let view = Chain::from(ChainInfo { public_rpc_url: None, ..info });
        assert_eq!(view.rpc_url, None, "no public URL => null, never the private one");
    }

    /// A store transport failure must not leak the store's address to clients.
    #[tokio::test]
    async fn remote_errors_are_replaced_by_a_generic_message() {
        // A real transport error: port 1 on loopback refuses the connection.
        // reqwest's Display for it names the URL — exactly what used to reach
        // the client's `errors[]`.
        let err = reqwest::Client::new()
            .get("http://127.0.0.1:1/internal-store/history")
            .send()
            .await
            .unwrap_err();
        let inner = bridge_core::remote::RemoteError::Http(err);
        let e = anyhow::Error::from(inner).context("history");
        assert!(e.to_string().contains("history"), "premise: detail exists: {e}");
        assert!(format!("{e:?}").contains("internal-store"), "premise: the URL is in the detail");

        let msg = store_error(e).message;
        assert_eq!(msg, "signature store unavailable");
        assert!(!msg.contains("internal-store"));
    }

    /// Round 5, H-7. Every field that costs an upstream round trip must carry a
    /// price, or `limit_complexity` bounds nothing: `stats` and `submission` cost
    /// the default 1, so thousands of ALIASES of them fitted one body and
    /// async-graphql resolved them concurrently — thousands of simultaneous
    /// full-page store reads from one anonymous POST.
    #[tokio::test]
    async fn aliasing_a_store_read_is_bounded_by_complexity() {
        let dir = std::env::temp_dir().join(format!("graphql-api-alias-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let schema = async_graphql::Schema::build(
            Query,
            async_graphql::EmptyMutation,
            async_graphql::EmptySubscription,
        )
        .limit_complexity(8000)
        .data(ApiState {
            backend: Arc::new(StoreBackend::file(&dir).unwrap()),
            threshold: Some(2),
            chains: Chains::new(),
            registry: vec![],
            swaps: Swaps::new(),
        })
        .finish();

        let aliased = |field: &str, n: usize| {
            let body: String =
                (0..n).map(|i| format!("a{i}:{field} ")).collect();
            format!("{{ {body} }}")
        };

        // Each `stats` now costs STORE_READ_COST, so a flood is refused before a
        // single store read happens. At the old cost of 1 this was admitted.
        let res = schema.execute(aliased("stats{total}", 200)).await;
        assert!(!res.errors.is_empty(), "an aliased stats flood must be refused");
        assert!(
            res.errors[0].message.to_lowercase().contains("complex"),
            "{:?}",
            res.errors
        );

        // A small page must still pay for the fetch it causes: the list formula is
        // additive, so `limit: 1` no longer scores 1 while pulling a full page.
        let res = schema.execute(aliased("submissions(limit:1){nonce}", 200)).await;
        assert!(!res.errors.is_empty(), "an aliased limit-1 flood must be refused");

        // Ordinary use is unaffected.
        assert!(schema.execute("{ stats { total } }").await.errors.is_empty());
        assert!(schema
            .execute(&aliased("stats{total}", 10))
            .await
            .errors
            .is_empty());
    }

    /// The complexity multiplier is what turns `limit_complexity` into a bound
    /// on `eth_call` fan-out. Before: `{ submissions { executed cancelled
    /// status } }` had complexity 4 whatever the table size.
    #[tokio::test]
    async fn list_complexity_scales_with_page_size_and_chain_reads() {
        let dir = std::env::temp_dir().join(format!("graphql-api-complexity-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state = ApiState {
            backend: Arc::new(StoreBackend::file(&dir).unwrap()),
            threshold: Some(2),
            chains: Chains::new(),
            registry: vec![],
            swaps: Swaps::new(),
        };
        let schema = async_graphql::Schema::build(
            Query,
            async_graphql::EmptyMutation,
            async_graphql::EmptySubscription,
        )
        .limit_complexity(8000)
        .data(state)
        .finish();

        // 200 rows x (1 + 3 x 20) = 12,200 > 8000: refused before any resolver runs.
        let res = schema
            .execute("{ submissions(limit: 200) { submissionId executed cancelled status } }")
            .await;
        assert!(!res.errors.is_empty(), "must be refused");
        assert!(res.errors[0].message.to_lowercase().contains("complex"), "{:?}", res.errors);

        // 200 rows x (1 + 20) = 4,200: admitted (and, on an empty store, empty).
        let res = schema.execute("{ submissions(limit: 200) { submissionId status } }").await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);

        // The frontend's exact shape, default page: admitted.
        let res = schema
            .execute(
                "{ submissions { submissionId debridgeId amount chainIdFrom chainIdTo nonce receiver \
                   nativeSender signatureCount meetsThreshold status signatures { signer } } }",
            )
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);

        // `history` and `swapHistory` carry the same multiplier.
        let res = schema
            .execute("{ history(limit: 200) { submissionId status swapIntent { tokenIn } } }")
            .await;
        // (a dir-backed store has no history; the point is that it got PAST
        // validation and into the resolver, which errors on the backend.)
        assert!(res.errors.iter().all(|e| !e.message.to_lowercase().contains("complex")), "{:?}", res.errors);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A mock EVM JSON-RPC answering every `eth_call` with `reply` (a result hex
    /// string, or an `error` object), counting calls. Returns its URL.
    async fn mock_evm_rpc(reply: serde_json::Value, calls: Arc<std::sync::atomic::AtomicUsize>) -> String {
        use axum::{routing::post, Json, Router};
        let app = Router::new().route(
            "/",
            post(move |Json(req): Json<serde_json::Value>| {
                let reply = reply.clone();
                let calls = calls.clone();
                async move {
                    assert_eq!(req["method"], "eth_call");
                    calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let mut body = serde_json::json!({"jsonrpc": "2.0", "id": req["id"]});
                    if reply.get("code").is_some() {
                        body["error"] = reply;
                    } else {
                        body["result"] = reply;
                    }
                    Json(body)
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    /// An RPC that answers per FUNCTION, keyed by 4-byte selector, falling back
    /// to `default` for anything else. The single-reply [`mock_evm_rpc`] cannot
    /// serve a resolver that reads two different functions — it would hand a
    /// `bridgeDecimalsFor` tuple back to `decimals()`, which decodes as
    /// whatever its first word happens to be.
    async fn mock_evm_rpc_per_selector(
        replies: Vec<(&'static str, serde_json::Value)>,
        default: serde_json::Value,
    ) -> String {
        use axum::{routing::post, Json, Router};
        let replies: std::collections::HashMap<String, serde_json::Value> =
            replies.into_iter().map(|(s, v)| (s.to_string(), v)).collect();
        let app = Router::new().route(
            "/",
            post(move |Json(req): Json<serde_json::Value>| {
                let replies = replies.clone();
                let default = default.clone();
                async move {
                    // Alloy sends the calldata as `input`; older clients use
                    // `data`. Accept both so the dispatch cannot silently fall
                    // through to the default and "pass" for the wrong reason.
                    let call = &req["params"][0];
                    let data = call["input"]
                        .as_str()
                        .or_else(|| call["data"].as_str())
                        .unwrap_or_default()
                        .to_string();
                    assert!(!data.is_empty(), "eth_call with no calldata: {req}");
                    let selector = data.get(2..10).unwrap_or_default();
                    let result = replies.get(selector).cloned().unwrap_or(default);
                    Json(serde_json::json!({"jsonrpc": "2.0", "id": req["id"], "result": result}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    /// A one-word `uint8` return, for `decimals()`.
    fn u8_reply(v: u8) -> serde_json::Value {
        let mut w = [0u8; 32];
        w[31] = v;
        serde_json::Value::String(format!("0x{}", alloy_primitives::hex::encode(w)))
    }

    /// `bridgeDecimalsFor` -> `(set, bridgeDecimals, localDecimals, localToken)`.
    fn corridor_reply(set: bool, bridge: u8, local: u8, token: &str) -> serde_json::Value {
        let mut w = [0u8; 128];
        w[31] = set as u8;
        w[63] = bridge;
        w[95] = local;
        let addr: alloy_primitives::Address = token.parse().unwrap();
        w[108..128].copy_from_slice(addr.as_slice());
        serde_json::Value::String(format!("0x{}", alloy_primitives::hex::encode(w)))
    }

    /// `bridgeDecimalsOf` -> `(set, bridgeDecimals, localDecimals)`, ABI-encoded.
    fn scale_reply(set: bool, bridge: u8, local: u8) -> serde_json::Value {
        let mut w = [0u8; 96];
        w[31] = set as u8;
        w[63] = bridge;
        w[95] = local;
        serde_json::Value::String(format!("0x{}", alloy_primitives::hex::encode(w)))
    }

    const TOKEN: &str = "0x00000000000000000000000000000000000000aa";
    const GATE: &str = "0x00000000000000000000000000000000000000bb";

    /// An API whose registry lists TOKEN on chain 11155111 at `listed` bridge
    /// decimals, with that chain's gate served by `rpc`. Returns the state and
    /// the TOKEN's debridgeId.
    fn scale_state(rpc: &str, listed: u8) -> (ApiState, String) {
        let dir = std::env::temp_dir().join(format!("graphql-api-scale-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut chains = Chains::new();
        chains.add(11155111, rpc, GATE).unwrap();
        let registry = vec![ChainInfo {
            chain_id: 11155111,
            name: "Sepolia".into(),
            rpc_url: Some(rpc.into()),
            public_rpc_url: None,
            gate: Some(GATE.into()),
            token: None,
            tokens: vec![crate::chain::TokenInfo {
                symbol: "TST".into(),
                address: TOKEN.into(),
                bridge_decimals: Some(listed),
            }],
            router: None,
            swap_pool: None,
        }];
        let id = bridge_core::debridge_id(
            alloy_primitives::U256::from(11155111u64),
            TOKEN.parse().unwrap(),
        );
        let state = ApiState {
            backend: Arc::new(StoreBackend::file(&dir).unwrap()),
            threshold: None,
            chains,
            registry,
            swaps: Swaps::new(),
        };
        (state, format!("{id:#x}"))
    }

    /// Audit 2026-09-16 (LOW): `bridgeDecimals` came from the operator-edited
    /// registry and was never compared with the gate. A registry saying 18 for an
    /// asset the gate scales at 6 made the explorer show every amount of it a
    /// trillion times too small.
    #[tokio::test]
    async fn a_registry_scale_the_gate_disagrees_with_is_not_served() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let url = mock_evm_rpc(scale_reply(true, 6, 18), calls.clone()).await;
        let (st, id) = scale_state(&url, 18);
        assert_eq!(st.bridge_decimals_of(&id).await, None, "registry 18 vs gate 6");
    }

    /// Agreement is served, and — a registration being write-once — costs one
    /// `eth_call` for the life of the process, not one per row.
    #[tokio::test]
    async fn an_agreeing_scale_is_served_and_read_once() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let url = mock_evm_rpc(scale_reply(true, 6, 18), calls.clone()).await;
        let (st, id) = scale_state(&url, 6);
        for _ in 0..5 {
            assert_eq!(st.bridge_decimals_of(&id).await, Some(6));
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// The gate has no scale for the token (unset, or a pre-decimals gate that
    /// reverts): nothing confirms the registry, so nothing is served.
    #[tokio::test]
    async fn an_unregistered_or_reverting_gate_serves_null() {
        for reply in [
            scale_reply(false, 0, 0),
            serde_json::json!({"code": 3, "message": "execution reverted", "data": "0x"}),
        ] {
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let url = mock_evm_rpc(reply.clone(), calls.clone()).await;
            let (st, id) = scale_state(&url, 6);
            assert_eq!(st.bridge_decimals_of(&id).await, None, "{reply}");
        }
    }

    /// A gate that cannot be reached is not a disagreement: the registry's figure
    /// stands rather than blanking the explorer over one slow RPC.
    #[tokio::test]
    async fn an_unreachable_gate_falls_back_to_the_registry() {
        let (st, id) = scale_state("http://127.0.0.1:1", 6);
        assert_eq!(st.bridge_decimals_of(&id).await, Some(6));
    }

    /// The `chains` query's per-token figure goes through the same check.
    #[tokio::test]
    async fn the_chains_query_applies_the_same_check() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let url = mock_evm_rpc(scale_reply(true, 6, 18), calls.clone()).await;
        let (st, _) = scale_state(&url, 18);
        let schema = async_graphql::Schema::build(Query, async_graphql::EmptyMutation, async_graphql::EmptySubscription)
            .data(st)
            .finish();
        let res = schema.execute("{ chains { tokens { symbol bridgeDecimals } } }").await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let json = res.data.into_json().unwrap();
        assert_eq!(json["chains"][0]["tokens"][0]["bridgeDecimals"], serde_json::Value::Null, "{json}");
    }

    /// `bridgeDecimals` now costs a CHAIN_READ, because it can reach the gate
    /// (M-11) — so it counts against the H-7 complexity budget where it used to
    /// cost 1. The UI's own history query must still fit, or this fix breaks
    /// the page it was meant to fix.
    ///
    /// The query below is copied from `frontend/src/api/client.ts`
    /// (`fetchHistory`), which sends no `limit` and so takes the 50-row default.
    #[tokio::test]
    async fn the_frontends_history_query_still_fits_the_complexity_budget() {
        let dir = std::env::temp_dir().join(format!("graphql-api-cost-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let schema = async_graphql::Schema::build(Query, async_graphql::EmptyMutation, async_graphql::EmptySubscription)
            .limit_complexity(8000)
            .data(ApiState {
                backend: Arc::new(StoreBackend::file(&dir).unwrap()),
                threshold: Some(2),
                chains: Chains::new(),
                registry: vec![],
                swaps: Swaps::new(),
            })
            .finish();

        const UI_HISTORY: &str = r#"query Hist($filter: HistoryFilter) {
           history(filter: $filter) {
             submissionId debridgeId amount bridgeDecimals chainIdFrom chainIdTo nonce receiver
             status claimTx signatureCount createdAt updatedAt
             stuck refundStatus refundTx cancelTx token
             cancelSignatureCount refundSignatureCount
             swapIntent {
               tokenIn amountIn stableOut finalToken finalReceiver
               finalizeTx finalizeAmountOut finalizeFallback finalizedAt
             }
           }
         }"#;
        let res = schema.execute(UI_HISTORY).await;
        let complexity_refused = res.errors.iter().any(|e| e.message.contains("too complex"));
        assert!(!complexity_refused, "the UI's own query was refused: {:?}", res.errors);

        // The budget still bites: asking for the whole 200-row page WITH the
        // three swap scales is 200 real chain reads, and is refused.
        let greedy = UI_HISTORY.replace("history(filter: $filter)", "history(filter: $filter, limit: 200)").replace(
            "finalizeFallback finalizedAt",
            "finalizeFallback finalizedAt amountInDecimals stableOutDecimals finalizeAmountOutDecimals",
        );
        let res = schema.execute(&greedy).await;
        assert!(
            res.errors.iter().any(|e| e.message.contains("too complex")),
            "200 rows of chain reads should not be free: {:?}",
            res.errors
        );
    }

    /// M-11's root cause. `scripts/run.sh` never emits `bridge_decimals` and
    /// the tracked `docker/configs/chains.json` omits it, so the registry
    /// lookup resolved NOTHING on those stacks and every `amount` came back
    /// with a null scale — which the explorer then formatted with the ERC-20's
    /// own decimals, rendering a 1,000-token transfer as `0`.
    ///
    /// The gate that produced the amount can always be asked instead.
    #[tokio::test]
    async fn a_registry_without_bridge_decimals_still_resolves_from_the_source_gate() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let url = mock_evm_rpc(scale_reply(true, 6, 18), calls.clone()).await;
        let (mut st, id) = scale_state(&url, 6);
        // Exactly what run.sh writes: a token with no `bridge_decimals`.
        st.registry[0].tokens[0].bridge_decimals = None;

        assert_eq!(st.bridge_decimals_of(&id).await, None, "registry alone cannot say");
        assert_eq!(st.amount_scale(&id, 11155111, TOKEN).await, Some(6), "the gate can");
    }

    /// The fallback needs a token to ask about, and must not invent one: a row
    /// from before the refund path has no `token`, and a Solana source has no
    /// EVM gate. Both stay null so a client shows raw units.
    #[tokio::test]
    async fn an_unaskable_source_leaves_the_scale_null() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let url = mock_evm_rpc(scale_reply(true, 6, 18), calls.clone()).await;
        let (mut st, id) = scale_state(&url, 6);
        st.registry[0].tokens[0].bridge_decimals = None;

        assert_eq!(st.amount_scale(&id, 11155111, "").await, None, "no token recorded");
        assert_eq!(st.amount_scale(&id, 7565164, TOKEN).await, None, "no gate for a Solana source");
        assert_eq!(st.amount_scale(&id, 11155111, "not-an-address").await, None);
    }

    /// M-12. `amountIn`, `stableOut` and `finalizeAmountOut` are local amounts
    /// of different tokens on different chains, served beside a wire `amount`.
    /// Each must declare its own scale.
    #[tokio::test]
    async fn every_swap_amount_declares_the_scale_it_is_in() {
        // `decimals()` -> 18 for whichever token is asked.
        let url = mock_evm_rpc_per_selector(vec![("313ce567", u8_reply(18))], u8_reply(18)).await;
        let (st, _) = scale_state(&url, 6);

        let intent = SwapIntent::from_info(
            SwapBridgeInfo {
                token_in: "0x00000000000000000000000000000000000000c1".into(),
                amount_in: "1000000000000000000".into(),
                stable_out: "3180000000".into(),
                final_token: "0x00000000000000000000000000000000000000c2".into(),
                final_receiver: "0x00000000000000000000000000000000000000c3".into(),
                finalize_tx: None,
                finalize_amount_out: None,
                finalize_fallback: None,
                finalized_at: None,
            },
            11155111,
            11155111,
            Some(TOKEN.into()),
            "0x".to_string() + &"11".repeat(32),
        );

        let json = resolve_intent(st, intent).await;
        // Each local amount now says what it is denominated in.
        assert_eq!(json["intent"]["amountInDecimals"], 18, "{json}");
        assert_eq!(json["intent"]["stableOutDecimals"], 18, "{json}");
        // Nothing has been delivered yet, so there is no payout scale to give —
        // null, not a confidently wrong number.
        assert_eq!(json["intent"]["finalizeAmountOutDecimals"], serde_json::Value::Null, "{json}");
    }

    /// The payout token differs between a normal finalize and a fallback: the
    /// user's `finalToken` versus the bridged stable. Serving one scale for
    /// both is the M-12 bug in miniature, so the fallback resolves through the
    /// destination gate's local token instead.
    #[tokio::test]
    async fn a_fallback_delivery_is_scaled_by_the_stable_that_arrived() {
        // The destination pays this corridor out in a 9-decimal local token,
        // while `finalToken` is an ordinary 18-decimal ERC-20.
        let url = mock_evm_rpc_per_selector(
            vec![
                ("93b06e9d", corridor_reply(true, 6, 9, "0x00000000000000000000000000000000000000dd")),
                ("313ce567", u8_reply(18)),
            ],
            u8_reply(18),
        )
        .await;
        let (st, _) = scale_state(&url, 6);

        let mut info = SwapBridgeInfo {
            token_in: "0x00000000000000000000000000000000000000c1".into(),
            amount_in: "1".into(),
            stable_out: "1".into(),
            final_token: "0x00000000000000000000000000000000000000c2".into(),
            final_receiver: "0x00000000000000000000000000000000000000c3".into(),
            finalize_tx: Some("0xdead".into()),
            finalize_amount_out: Some("1000000000".into()),
            finalize_fallback: Some(true),
            finalized_at: None,
        };
        let id = "0x".to_string() + &"11".repeat(32);
        let intent = SwapIntent::from_info(info.clone(), 11155111, 11155111, Some(TOKEN.into()), id.clone());
        let json = resolve_intent(st, intent).await;
        assert_eq!(json["intent"]["finalizeAmountOutDecimals"], 9, "fallback pays the local stable: {json}");

        // The same row WITHOUT the fallback is scaled by `finalToken` instead —
        // 18 here, against the stable's 9. One label for both would be wrong
        // for one of them, which is M-12.
        info.finalize_fallback = Some(false);
        let url2 = mock_evm_rpc_per_selector(
            vec![
                ("93b06e9d", corridor_reply(true, 6, 9, "0x00000000000000000000000000000000000000dd")),
                ("313ce567", u8_reply(18)),
            ],
            u8_reply(18),
        )
        .await;
        let (st2, _) = scale_state(&url2, 6);
        let intent2 = SwapIntent::from_info(info, 11155111, 11155111, Some(TOKEN.into()), id);
        let json2 = resolve_intent(st2, intent2).await;
        assert_eq!(json2["intent"]["finalizeAmountOutDecimals"], 18, "normal finalize pays finalToken: {json2}");
    }

    /// A pool trade crosses two tokens, so its two amounts are in two scales.
    /// Serving one number for both (which is what a client had to guess from
    /// the chain) misreads whichever side is not the chain's default token.
    #[tokio::test]
    async fn the_two_sides_of_a_swap_carry_their_own_decimals() {
        const WETH: &str = "0x00000000000000000000000000000000000000e1";
        const USDC: &str = "0x00000000000000000000000000000000000000e2";
        // `decimals()` answers per TOKEN: the calldata is the same selector for
        // both, so dispatch on the `to` address instead.
        use axum::{routing::post, Json, Router};
        let app = Router::new().route(
            "/",
            post(|Json(req): Json<serde_json::Value>| async move {
                let to = req["params"][0]["to"].as_str().unwrap_or_default().to_ascii_lowercase();
                let d: u8 = if to == USDC { 6 } else { 18 };
                let mut w = [0u8; 32];
                w[31] = d;
                Json(serde_json::json!({
                    "jsonrpc": "2.0", "id": req["id"],
                    "result": format!("0x{}", alloy_primitives::hex::encode(w)),
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let (st, _) = scale_state(&format!("http://{addr}"), 6);

        let row = SwapHistoryEntry {
            chain_id: 11155111,
            tx_hash: "0xfeed".into(),
            sender: "0x00000000000000000000000000000000000000e3".into(),
            receiver: "0x00000000000000000000000000000000000000e4".into(),
            token_in: WETH.into(),
            token_out: USDC.into(),
            amount_in: "1000000000000000000".into(),
            amount_out: "3180000000".into(),
            block_number: 1,
            created_at: "2026-09-21T00:00:00Z".into(),
        };

        struct SwapRoot(std::sync::Mutex<Option<SwapHistoryEntry>>);
        #[async_graphql::Object]
        impl SwapRoot {
            async fn swap(&self) -> SwapHistoryEntry {
                self.0.lock().unwrap().take().expect("one resolution per root")
            }
        }
        let schema = async_graphql::Schema::build(
            SwapRoot(std::sync::Mutex::new(Some(row))),
            async_graphql::EmptyMutation,
            async_graphql::EmptySubscription,
        )
        .data(st)
        .finish();
        let res = schema.execute("{ swap { amountInDecimals amountOutDecimals } }").await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let json = res.data.into_json().unwrap();
        assert_eq!(json["swap"]["amountInDecimals"], 18, "{json}");
        assert_eq!(json["swap"]["amountOutDecimals"], 6, "{json}");
    }

    /// Resolve a `SwapIntent`'s fields the way a client reaches them: through a
    /// real GraphQL execution with `ApiState` in scope.
    async fn resolve_intent(st: ApiState, intent: SwapIntent) -> serde_json::Value {
        struct IntentRoot(std::sync::Mutex<Option<SwapIntent>>);
        #[async_graphql::Object]
        impl IntentRoot {
            async fn intent(&self) -> SwapIntent {
                self.0.lock().unwrap().take().expect("one resolution per root")
            }
        }
        let schema = async_graphql::Schema::build(
            IntentRoot(std::sync::Mutex::new(Some(intent))),
            async_graphql::EmptyMutation,
            async_graphql::EmptySubscription,
        )
        .data(st)
        .finish();
        let res = schema
            .execute("{ intent { amountIn amountInDecimals stableOutDecimals finalizeAmountOutDecimals } }")
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        res.data.into_json().unwrap()
    }

    /// A Solana mint is not an EVM address and has no single gate registration:
    /// its registry figure must still be served, not dropped to `null`.
    #[tokio::test]
    async fn a_non_evm_token_keeps_its_registry_scale() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let url = mock_evm_rpc(scale_reply(true, 6, 18), calls.clone()).await;
        let (mut st, _) = scale_state(&url, 6);
        st.registry.push(ChainInfo {
            chain_id: 7565164,
            name: "Solana Devnet".into(),
            rpc_url: None,
            public_rpc_url: None,
            gate: Some("Bvh4JxhWBCFXfc4iu8Cm9PCw86EAH4Yn39pHpzwnQFc1".into()),
            token: None,
            tokens: vec![crate::chain::TokenInfo {
                symbol: "WRAP".into(),
                address: "Bqt4xDpu6oEPgTgVLjZVQ56hFUGo2F4M8zFuK98NHe32".into(),
                bridge_decimals: Some(9),
            }],
            router: None,
            swap_pool: None,
        });
        let schema = async_graphql::Schema::build(Query, async_graphql::EmptyMutation, async_graphql::EmptySubscription)
            .data(st)
            .finish();
        let res = schema.execute("{ chains { chainId tokens { symbol bridgeDecimals } } }").await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let json = res.data.into_json().unwrap();
        let sol = json["chains"].as_array().unwrap().iter().find(|c| c["chainId"] == 7565164).expect("solana chain");
        assert_eq!(sol["tokens"][0]["bridgeDecimals"], 9, "{json}");
    }

    /// A log sink the tests can read back.
    #[derive(Clone, Default)]
    struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Captured {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A caller-chosen `symbol` must not be able to write a log line of its own.
    #[test]
    fn a_hostile_symbol_cannot_forge_a_log_line() {
        let sink = Captured::default();
        let writer = sink.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let forged = "TST\n2026-09-17T00:00:00Z  INFO keeper: claim submitted submission_id=0xdead";
        tracing::subscriber::with_default(subscriber, || warn_unmapped_symbol(1, 2, forged));

        let out = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        assert_eq!(out.lines().count(), 1, "one event, one line — got:\n{out}");
        assert!(out.contains(r"TST\n2026"), "the newline is visible, escaped: {out}");
    }

    /// ...while a store-side validation error (no URL in it) stays informative.
    #[test]
    fn store_validation_errors_pass_through() {
        let e = anyhow::Error::from(bridge_core::store::StoreError::BadField("signer"));
        let msg = store_error(e).message;
        assert!(msg.contains("signer"), "got: {msg}");
    }
}
