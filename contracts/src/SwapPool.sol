// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

/// @title SwapPool
/// @notice A same-chain, pegged-price swap pool for bridge tokens. Every listed
///         token has an admin/oracle-set USD price; ONE stablecoin is the core
///         unit of account (price fixed at 1.0, immutable). A swap converts
///         `tokenIn -> tokenOut` at the pegged rate, normalising for token
///         decimals, and is HARD-CAPPED by the output token's locked reserve —
///         so a swap can never drain a pool ("max swap up to token lock").
/// @dev    Deliberately mirrors Gate.sol's security idioms (SafeERC20, CEI,
///         two-step ownership, guardian + paused circuit breaker, custom errors,
///         rich events). Liquidity is PROTOCOL-OWNED: the owner seeds/withdraws
///         reserves; there are no LP shares in v1. Reserves are tracked
///         INTERNALLY (not via balanceOf) so a raw token donation cannot corrupt
///         pricing or the cap, and fee-on-transfer tokens are caught by delta.
///
///         This is the same-chain primitive. A future cross-chain SwapRouter can
///         compose swap() with Gate.send()/claim() WITHOUT changing this contract
///         (swap() already takes an explicit `to` recipient).
contract SwapPool is ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// @dev USD prices are fixed-point, scaled by PRICE_ONE (1e18). The stable's
    ///      price is exactly PRICE_ONE and can never be changed.
    uint256 public constant PRICE_ONE = 1e18;
    /// @dev basis-point denominator for the fee and the price-deviation guard.
    uint16 public constant BPS_DENOM = 10_000;

    struct TokenInfo {
        bool listed;
        uint8 decimals; // cached at listing time
        uint256 price; // USD price, PRICE_ONE-scaled
        uint256 reserve; // internal accounting — this IS the swap lock
    }

    // --- registry ---
    mapping(address token => TokenInfo) public tokens;
    /// @dev the core-price token; tokens[stable].price == PRICE_ONE forever.
    address public immutable stable;

    // --- governance / roles (mirrors Gate.sol) ---
    address public owner;
    address public pendingOwner;
    /// @dev the only role permitted to move prices (may equal owner, but is
    ///      separable so a low-trust price feeder cannot also move liquidity).
    address public oracle;

    // --- circuit breaker ---
    bool public paused;
    address public guardian;

    // --- economic parameters ---
    /// @dev swap fee in bps, charged on the USD value (accrues into reserves).
    ///
    ///      It is ALSO the largest move a single {setPrice} may make — see
    ///      {priceStepCapBps}. A pool at fee 0 can therefore re-assert its prices
    ///      (the staleness refresh) but never move them: give it a fee first.
    uint16 public feeBps;
    /// @dev max allowed price move per setPrice() call, in bps (anti-fat-finger /
    ///      anti-compromise). Applies only to UPDATES (not the first price). The
    ///      cap actually enforced is the LESSER of this and {feeBps}; see
    ///      {priceStepCapBps}.
    uint16 public maxPriceDeviationBps;
    /// @dev minimum wall-clock gap between two reprices of the SAME token. The
    ///      per-call deviation cap alone only bounds one step; without a time gate
    ///      a compromised oracle could call setPrice() many times in a single
    ///      block, each within the cap, and walk the price arbitrarily. Together
    ///      the two bound the price to at most `maxPriceDeviationBps` per interval.
    uint256 public minPriceUpdateInterval;
    /// @dev last repricing time per token (0 => never repriced since listing; the
    ///      first update is always allowed).
    mapping(address => uint256) public lastPriceUpdate;
    /// @dev when a token's CURRENT price was established — set by `listToken` as
    ///      well as `setPrice`, unlike `lastPriceUpdate`, which exists only to gate
    ///      the repricing cooldown and deliberately stays zero until the first
    ///      update so that update is free. Read only by the staleness guard.
    mapping(address => uint256) public priceSetAt;
    /// @dev how old a token's price may be before `quote`/`swap` refuse it.
    ///      Zero disables the check.
    ///
    ///      THE RATE LIMITS DO NOT COVER THIS. `maxPriceDeviationBps` and
    ///      `minPriceUpdateInterval` bound how fast a price may MOVE; neither
    ///      bounds how OLD it may be. `swap` read `t.price` and never looked at
    ///      `lastPriceUpdate`, so a stalled or halted oracle kept quoting its last
    ///      figure indefinitely and every swap against it was arbitrage — running
    ///      until the output reserve hit the lock, which is the drain bound, not a
    ///      defence. The oracle role is separable from the owner precisely because
    ///      it is expected to be lower-trust and more failure-prone, so its failure
    ///      mode has to be "the pool stops", not "the pool pays out at yesterday's
    ///      price".
    uint256 public maxPriceAge;

    // --- events ---
    event TokenListed(address indexed token, uint256 price, uint8 decimals);
    event TokenDelisted(address indexed token);
    event PriceSet(address indexed token, uint256 oldPrice, uint256 newPrice);
    event LiquiditySeeded(address indexed token, uint256 amount, uint256 reserve);
    event LiquidityWithdrawn(address indexed token, uint256 amount, uint256 reserve, address to);
    event Swapped(
        address indexed sender,
        address indexed tokenIn,
        address indexed tokenOut,
        uint256 amountIn,
        uint256 amountOut,
        address to
    );
    event FeeSet(uint16 feeBps);
    event MaxPriceDeviationSet(uint16 bps);
    event MinPriceUpdateIntervalSet(uint256 interval);
    event MaxPriceAgeSet(uint256 maxAge);
    event OracleSet(address indexed oracle);
    // governance / pause (same shape as Gate.sol)
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event GuardianSet(address indexed guardian);
    event Paused(address indexed account);
    event Unpaused(address indexed account);

    // --- errors ---
    error NotOwner();
    error NotOracle();
    error ZeroAddress();
    error TokenNotListed(address token);
    error TokenAlreadyListed(address token);
    error SameToken();
    error ZeroAmount();
    error ZeroPrice();
    /// @dev the requested output exceeds the pool's lock for that token.
    error ExceedsLock(uint256 want, uint256 reserve);
    /// @dev computed output was below the caller's minimum (slippage / stale price).
    error Slippage(uint256 got, uint256 min);
    error StableRepriceForbidden();
    /// @dev delisting the stable would let it be re-listed at any price, which is
    ///      `StableRepriceForbidden` with extra steps. See {delistToken}.
    error StableDelistForbidden();
    error PriceDeviationTooHigh(uint256 oldPrice, uint256 newPrice, uint16 maxBps);
    /// @dev {setPrice}'s compare-and-set failed: the price on chain is not the
    ///      one the oracle planned its step from (audit 2026-10-02, M7-4).
    error PriceChanged(address token, uint256 expected, uint256 actual);
    /// @dev setPrice() called again before the per-token cooldown elapsed.
    error PriceUpdateTooSoon(address token, uint256 nextAllowed);
    /// @dev the token's price is older than {maxPriceAge}; the pool refuses to
    ///      trade at a figure the oracle has stopped confirming.
    error StalePrice(address token, uint256 setAt, uint256 maxAge);
    error ReserveNonZero();
    error FeeTooHigh();
    error DeviationTooHigh();
    error EnforcedPause();
    error NotAuthorizedToPause();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyOracle() {
        if (msg.sender != oracle) revert NotOracle();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert EnforcedPause();
        _;
    }

    /// @param stable_             the core-price token (price pinned to PRICE_ONE)
    /// @param maxPriceDeviationBps_ initial per-update price cap in bps (e.g. 1000 = 10%)
    constructor(address stable_, uint16 maxPriceDeviationBps_) {
        if (stable_ == address(0)) revert ZeroAddress();
        if (maxPriceDeviationBps_ == 0 || maxPriceDeviationBps_ > BPS_DENOM) revert DeviationTooHigh();

        owner = msg.sender;
        oracle = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
        emit OracleSet(msg.sender);

        maxPriceDeviationBps = maxPriceDeviationBps_;
        emit MaxPriceDeviationSet(maxPriceDeviationBps_);

        // Default cooldown: at most one deviation-capped step per hour, so a
        // compromised oracle cannot walk the price within a block/many blocks.
        // Owner-tunable via setMinPriceUpdateInterval.
        minPriceUpdateInterval = 1 hours;
        emit MinPriceUpdateIntervalSet(1 hours);

        // Default staleness bound: a day. Deliberately non-zero, because the
        // dangerous configuration should be the one an operator has to choose.
        // Tune it to the oracle's real cadence via setMaxPriceAge.
        maxPriceAge = 1 days;
        emit MaxPriceAgeSet(1 days);

        stable = stable_;
        uint8 dec = IERC20Metadata(stable_).decimals();
        tokens[stable_] = TokenInfo({listed: true, decimals: dec, price: PRICE_ONE, reserve: 0});
        // The stable is exempt from the staleness check (its peg is immutable, so
        // there is nothing for an oracle to refresh), but stamp it anyway so the
        // view reads consistently for every listed token.
        priceSetAt[stable_] = block.timestamp;
        emit TokenListed(stable_, PRICE_ONE, dec);
    }

    // ---------------------------------------------------------------------
    // Governance
    // ---------------------------------------------------------------------

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotOwner();
        emit OwnershipTransferred(owner, pendingOwner);
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    function setOracle(address newOracle) external onlyOwner {
        if (newOracle == address(0)) revert ZeroAddress();
        oracle = newOracle;
        emit OracleSet(newOracle);
    }

    function setGuardian(address newGuardian) external onlyOwner {
        guardian = newGuardian;
        emit GuardianSet(newGuardian);
    }

    function setFee(uint16 newFeeBps) external onlyOwner {
        // cap the fee well below 100% so a swap can never round to a zero/negative
        // payout by fee alone (defensive; 1000 = 10%).
        if (newFeeBps > 1000) revert FeeTooHigh();
        feeBps = newFeeBps;
        emit FeeSet(newFeeBps);
    }

    function setMaxPriceDeviation(uint16 bps) external onlyOwner {
        if (bps == 0 || bps > BPS_DENOM) revert DeviationTooHigh();
        maxPriceDeviationBps = bps;
        emit MaxPriceDeviationSet(bps);
    }

    /// @notice Set the minimum gap between two reprices of the same token. Set to
    ///         0 only for instant-finality dev chains where oracle abuse is not a
    ///         concern; a real deployment should keep a nonzero cooldown so the
    ///         price can move at most `maxPriceDeviationBps` per interval.
    function setMinPriceUpdateInterval(uint256 interval) external onlyOwner {
        minPriceUpdateInterval = interval;
        emit MinPriceUpdateIntervalSet(interval);
    }

    /// @notice Set how old a token's price may be before the pool refuses to trade
    ///         it. Zero disables the check — dev chains only, for the same reason
    ///         {setMinPriceUpdateInterval} says.
    /// @dev    Sized against the oracle's cadence: comfortably longer than a normal
    ///         update interval, short enough that a dead feed stops the pool before
    ///         the market moves far enough to be worth arbitraging.
    function setMaxPriceAge(uint256 maxAge) external onlyOwner {
        maxPriceAge = maxAge;
        emit MaxPriceAgeSet(maxAge);
    }

    /// @dev Refuse a token whose price the oracle has stopped confirming.
    ///
    ///      The stable is exempt: its price is PRICE_ONE by construction and
    ///      `setPrice` refuses to move it, so there is no feed that could go stale.
    function _requireFreshPrice(address token) internal view {
        if (maxPriceAge == 0 || token == stable) return;
        uint256 setAt = priceSetAt[token];
        if (block.timestamp - setAt > maxPriceAge) {
            revert StalePrice(token, setAt, maxPriceAge);
        }
    }

    function pause() external {
        if (msg.sender != owner && msg.sender != guardian) revert NotAuthorizedToPause();
        if (!paused) {
            paused = true;
            emit Paused(msg.sender);
        }
    }

    function unpause() external onlyOwner {
        if (paused) {
            paused = false;
            emit Unpaused(msg.sender);
        }
    }

    // ---------------------------------------------------------------------
    // Token registry + pricing
    // ---------------------------------------------------------------------

    /// @notice List a token for swapping at an initial USD price (PRICE_ONE-scaled).
    /// @dev    Decimals are cached from IERC20Metadata. The stable is listed in the
    ///         constructor and can never be delisted, so it never reaches here.
    ///
    ///         RE-LISTING IS A REPRICE, and is bounded like one. `delistToken`
    ///         keeps the token's last price precisely so this can check against
    ///         it: without that, delist -> relist was an unbounded, instant
    ///         repricing path straight around `setPrice`'s deviation cap AND its
    ///         cooldown. The owner can already move liquidity, so this is not a
    ///         new theft primitive — but the rate limit is documented as a
    ///         security property, and a limit with a one-transaction bypass is
    ///         not one. The cooldown itself stays cleared on delist (finding
    ///         L-2): the FIRST `setPrice` after a listing is still free, it just
    ///         starts from a price the cap had a say in.
    function listToken(address token, uint256 price) external onlyOwner {
        if (token == address(0)) revert ZeroAddress();
        TokenInfo storage t = tokens[token];
        if (t.listed) revert TokenAlreadyListed(token);
        if (price == 0) revert ZeroPrice();

        uint256 previous = t.price; // nonzero only for a token listed before
        if (previous != 0) {
            uint256 diff = price > previous ? price - previous : previous - price;
            if (diff > Math.mulDiv(previous, maxPriceDeviationBps, BPS_DENOM)) {
                revert PriceDeviationTooHigh(previous, price, maxPriceDeviationBps);
            }
        }

        uint8 dec = IERC20Metadata(token).decimals();
        t.listed = true;
        t.decimals = dec;
        t.price = price;
        // A freshly listed price is a fresh price. Stamping here rather than
        // reusing `lastPriceUpdate` keeps the cooldown's "first update is free"
        // exemption intact while still giving the staleness clock a start.
        priceSetAt[token] = block.timestamp;
        // `reserve` is left alone rather than zeroed: `delistToken` already
        // requires it to be zero and a never-listed token has none, so there is
        // nothing to reset — and writing a zero here would be the one place a
        // real balance could be erased if that invariant ever slipped.
        emit TokenListed(token, price, dec);
    }

    /// @notice The largest move one {setPrice} may make, in bps of the current
    ///         price: the LESSER of {maxPriceDeviationBps} and {feeBps}.
    ///
    /// @dev    WHY THE FEE BOUNDS THE STEP (audit 2026-10-02, M7-3). Swaps fill at
    ///         exactly the oracle price, and a price-keeper's capped steps toward
    ///         its target are predictable without even watching the mempool. With
    ///         a step of `d` and a fee of `f`, a round trip around one update —
    ///         buy at the old price, sell at the new one — returns
    ///         `(1 - f)^2 * (1 + d)` of its capital going up, and
    ///         `(1 - f)^2 / (1 - d)` going down. At `d <= f` both are below 1
    ///         (`(1 - f)(1 - f^2)` and `1 - f`), so no sandwich around a single
    ///         update can profit, however large the capital: what used to be up
    ///         to `maxPriceDeviationBps` of the attacker's capital per update,
    ///         taken from reserves, is now a guaranteed loss. Rounding only helps:
    ///         the fee rounds up against the trader and every output floors.
    ///
    ///         The cost is tracking speed — the price moves at most one fee-sized
    ///         step per {minPriceUpdateInterval}. Size the fee and the interval
    ///         together against how fast the asset really moves; a price that lags
    ///         the market is arbitraged whatever this cap is.
    function priceStepCapBps() public view returns (uint16) {
        return feeBps < maxPriceDeviationBps ? feeBps : maxPriceDeviationBps;
    }

    /// @notice Update a token's pegged price (oracle-only), bounded by
    ///         {priceStepCapBps} and the per-token cooldown. The stable can never
    ///         be repriced.
    /// @param  expectedOld the price the oracle planned this step from. The call
    ///         reverts {PriceChanged} unless it is the price on chain right now.
    ///
    /// @dev    COMPARE-AND-SET (audit 2026-10-02, M7-4). The price-keeper steps
    ///         FROM the current on-chain price toward its target, and it learns
    ///         that price from an RPC endpoint. A lying endpoint could report any
    ///         figure and have the oracle key sign a "step toward target" that is
    ///         really a capped move AWAY from it, every interval. Binding the read
    ///         into the write makes a lie a revert instead of a wrong price: the
    ///         step the oracle signs is only ever applied to the price it was
    ///         computed from. There is deliberately no unconditional variant.
    function setPrice(address token, uint256 expectedOld, uint256 newPrice) external onlyOracle {
        TokenInfo storage t = tokens[token];
        if (!t.listed) revert TokenNotListed(token);
        if (token == stable) revert StableRepriceForbidden();
        if (newPrice == 0) revert ZeroPrice();

        uint256 oldPrice = t.price;
        if (oldPrice != expectedOld) revert PriceChanged(token, expectedOld, oldPrice);

        // Time gate: the first repricing after listing is free, but every
        // subsequent one must wait out the cooldown. This bounds the RATE of
        // change — with the per-call cap it caps movement to one step per
        // interval — so a compromised oracle cannot walk the price in a block.
        uint256 last = lastPriceUpdate[token];
        if (last != 0 && block.timestamp < last + minPriceUpdateInterval) {
            revert PriceUpdateTooSoon(token, last + minPriceUpdateInterval);
        }

        // |new - old| / old <= min(maxDeviation, fee)
        uint16 cap = priceStepCapBps();
        uint256 diff = newPrice > oldPrice ? newPrice - oldPrice : oldPrice - newPrice;
        if (diff > Math.mulDiv(oldPrice, cap, BPS_DENOM)) {
            revert PriceDeviationTooHigh(oldPrice, newPrice, cap);
        }

        t.price = newPrice;
        lastPriceUpdate[token] = block.timestamp;
        priceSetAt[token] = block.timestamp;
        emit PriceSet(token, oldPrice, newPrice);
    }

    /// @notice Delist a token. Only when its reserve is fully withdrawn, so we
    ///         never strand locked liquidity behind an unlisted entry.
    /// @dev    THE STABLE CAN NEVER BE DELISTED. Its price is the pool's unit of
    ///         account, fixed at PRICE_ONE, and `setPrice` refuses to move it.
    ///         Delisting was the way around that: delist (its reserve can be
    ///         drained to zero by the owner) and re-list at any price at all,
    ///         never touching `setPrice`. The "immutable" peg is what the
    ///         cross-chain SwapRouter's accounting rests on, so the escape hatch
    ///         is closed here rather than in `listToken`.
    function delistToken(address token) external onlyOwner {
        if (token == stable) revert StableDelistForbidden();
        TokenInfo storage t = tokens[token];
        if (!t.listed) revert TokenNotListed(token);
        if (t.reserve != 0) revert ReserveNonZero();
        // Flip the listing off but KEEP `price`: it is what bounds a future
        // re-listing (see listToken). `decimals` and `reserve` are both rewritten
        // or provably zero on the way back in.
        t.listed = false;
        // Clear the staleness clock with the listing it belonged to; `listToken`
        // restarts it. (`price` is deliberately KEPT — see above.)
        delete priceSetAt[token];
        // Clear the repricing clock with the listing it belonged to. `setPrice`
        // exempts the FIRST update after listing via `last == 0`; leaving a stale
        // timestamp here would carry into a future re-listing and block that
        // exemption, freezing the new price behind a cooldown it never earned.
        delete lastPriceUpdate[token];
        emit TokenDelisted(token);
    }

    // ---------------------------------------------------------------------
    // Liquidity (protocol-owned)
    // ---------------------------------------------------------------------

    /// @notice Seed (or top up) a token's reserve — the lock that bounds swaps.
    /// @dev    Credits reserve by the ACTUAL amount received (fee-on-transfer safe).
    function seedLiquidity(address token, uint256 amount) external onlyOwner {
        TokenInfo storage t = tokens[token];
        if (!t.listed) revert TokenNotListed(token);
        if (amount == 0) revert ZeroAmount();

        uint256 before = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        uint256 received = IERC20(token).balanceOf(address(this)) - before;

        t.reserve += received;
        emit LiquiditySeeded(token, received, t.reserve);
    }

    /// @notice Withdraw reserve (rebalancing / decommission / fee capture).
    function withdrawLiquidity(address token, uint256 amount, address to) external onlyOwner {
        TokenInfo storage t = tokens[token];
        if (!t.listed) revert TokenNotListed(token);
        if (amount == 0) revert ZeroAmount();
        if (to == address(0)) revert ZeroAddress();
        if (amount > t.reserve) revert ExceedsLock(amount, t.reserve);

        t.reserve -= amount; // effects before interaction
        IERC20(token).safeTransfer(to, amount);
        emit LiquidityWithdrawn(token, amount, t.reserve, to);
    }

    // ---------------------------------------------------------------------
    // Swap
    // ---------------------------------------------------------------------

    /// @notice Price `amountIn` of `tokenIn` into `tokenOut` at the pegged rate
    ///         (net of fee). Pure pricing — does NOT check the reserve cap.
    function quote(address tokenIn, address tokenOut, uint256 amountIn)
        public
        view
        returns (uint256 amountOut)
    {
        TokenInfo storage ti = tokens[tokenIn];
        TokenInfo storage to = tokens[tokenOut];
        if (!ti.listed) revert TokenNotListed(tokenIn);
        if (!to.listed) revert TokenNotListed(tokenOut);
        // A quote at a stale price is a quote nobody should act on, and callers
        // (SwapRouter's blocked-swap check among them) read this to decide whether
        // a swap is possible right now.
        _requireFreshPrice(tokenIn);
        _requireFreshPrice(tokenOut);
        return _amountOut(amountIn, ti.price, ti.decimals, to.price, to.decimals, feeBps);
    }

    /// @notice Swap `amountIn` of `tokenIn` for `tokenOut`, capped by the output
    ///         token's locked reserve. Sends the output to `to`.
    /// @param minAmountOut caller's slippage / stale-price floor
    function swap(address tokenIn, address tokenOut, uint256 amountIn, uint256 minAmountOut, address to)
        external
        whenNotPaused
        nonReentrant
        returns (uint256 amountOut)
    {
        if (tokenIn == tokenOut) revert SameToken();
        if (amountIn == 0) revert ZeroAmount();
        if (to == address(0)) revert ZeroAddress();

        TokenInfo storage ti = tokens[tokenIn];
        TokenInfo storage tOut = tokens[tokenOut];
        if (!ti.listed) revert TokenNotListed(tokenIn);
        if (!tOut.listed) revert TokenNotListed(tokenOut);
        // Before any funds move: refuse to trade a price the oracle has stopped
        // confirming. Checked on BOTH sides — either one being stale misprices the
        // pair, and it is the output side the arbitrage drains.
        _requireFreshPrice(tokenIn);
        _requireFreshPrice(tokenOut);

        // Pull first (fee-on-transfer safe) so pricing uses the amount actually
        // received. This is the only external call before we compute + book.
        uint256 balBefore = IERC20(tokenIn).balanceOf(address(this));
        IERC20(tokenIn).safeTransferFrom(msg.sender, address(this), amountIn);
        uint256 received = IERC20(tokenIn).balanceOf(address(this)) - balBefore;
        if (received == 0) revert ZeroAmount();

        amountOut = _amountOut(received, ti.price, ti.decimals, tOut.price, tOut.decimals, feeBps);
        if (amountOut == 0) revert ZeroAmount();
        if (amountOut < minAmountOut) revert Slippage(amountOut, minAmountOut);
        // THE LOCK: never pay out more than this token's reserve.
        if (amountOut > tOut.reserve) revert ExceedsLock(amountOut, tOut.reserve);

        // Effects before the outgoing interaction (CEI). The fee stays in the
        // pool as retained reserve value (reserveIn grows by the full input,
        // reserveOut shrinks by only the net output).
        ti.reserve += received;
        tOut.reserve -= amountOut;
        emit Swapped(msg.sender, tokenIn, tokenOut, received, amountOut, to);

        IERC20(tokenOut).safeTransfer(to, amountOut);
    }

    // ---------------------------------------------------------------------
    // Internal pricing
    // ---------------------------------------------------------------------

    /// @dev out = amountIn * priceIn * 10^decOut / (priceOut * 10^decIn), less fee.
    ///      Uses mulDiv (512-bit intermediate) to avoid overflow, and floors —
    ///      every rounding step favors the pool.
    function _amountOut(
        uint256 amountIn,
        uint256 priceIn,
        uint8 decIn,
        uint256 priceOut,
        uint8 decOut,
        uint16 fee
    ) internal pure returns (uint256) {
        // USD value of the input, PRICE_ONE-scaled.
        uint256 usd = Math.mulDiv(amountIn, priceIn, 10 ** decIn);
        if (fee != 0) {
            // fee rounds UP against the user (mulDiv ceil), pool keeps the dust.
            uint256 feeUsd = Math.mulDiv(usd, fee, BPS_DENOM, Math.Rounding.Ceil);
            usd = usd - feeUsd;
        }
        // Convert USD back into output-token units (floors).
        return Math.mulDiv(usd, 10 ** decOut, priceOut);
    }

    /// @notice Convenience view: the current maximum swap OUTPUT for a token
    ///         (its reserve) and that value in USD (PRICE_ONE-scaled).
    function maxSwapOut(address token) external view returns (uint256 reserve, uint256 usdValue) {
        TokenInfo storage t = tokens[token];
        if (!t.listed) revert TokenNotListed(token);
        reserve = t.reserve;
        usdValue = Math.mulDiv(reserve, t.price, 10 ** t.decimals);
    }
}
