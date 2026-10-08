// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Gate} from "./Gate.sol";
import {SwapPool} from "./SwapPool.sol";

/// @title SwapRouter
/// @notice Composes the same-chain {SwapPool} with the cross-chain {Gate} to turn
///         "swap TokenX on chain A into TokenY on chain B" into two atomic legs,
///         WITHOUT changing either underlying contract. One router is deployed per
///         chain and pointed at that chain's Gate + SwapPool.
///
/// @dev    The stablecoin is the cross-chain carrier: only the stable needs bridge
///         liquidity on every chain (the pricing-hub payoff). A transfer is:
///
///           on chain A  swapAndBridge(): TokenX --SwapPool--> stable
///                                        stable --Gate.send--> chainB
///                                        intent (TokenY, receiver, minOut) rides
///                                        in autoParams.data, which the Gate binds
///                                        into the submissionId.
///           off-chain: validators sign the Sent (unchanged); a keeper claims.
///           on chain B  Gate.claim():     releases the stable to THIS router
///                       finalize():       stable --SwapPool--> TokenY -> receiver
///
///         The destination leg is TRUSTLESS and needs no callback from the Gate:
///         `finalize` proves delivery by checking `Gate.executed[submissionId]`.
///         Because `amount` and the intent (in autoParams.data) are both committed
///         inside that id — signed by the validators — the router can trust that
///         exactly `amount` of the stable was delivered to it for this intent. A
///         per-id `finalized` guard makes it idempotent. A destination swap that
///         cannot run right now DEFERS (nothing settles, anyone may retry); only
///         after {FALLBACK_GRACE}, and only at the hand of the receiver or the
///         router's owner/guardian, is the carrier stable delivered instead — so
///         funds never strand, and no third party can pick the user's asset.
contract SwapRouter is ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// @notice the Gate this router bridges through (source send / dest claim).
    Gate public immutable gate;
    /// @notice the local SwapPool used for both swap legs.
    SwapPool public immutable pool;
    /// @notice the cross-chain carrier asset (must be listed on both pools).
    address public immutable stable;

    /// @notice Gas that must remain when the destination swap is attempted.
    ///
    /// @dev    GRIEFING GUARD. `_deliver` wraps `pool.swap` in try/catch so a
    ///         genuinely impossible swap (output over the pool lock, token
    ///         unlisted, slippage) falls back to delivering the stable instead of
    ///         stranding the funds. But `finalize` is PERMISSIONLESS and
    ///         `finalized[submissionId]` is set before the swap is attempted, so
    ///         without a floor here anyone could call it with just enough gas that
    ///         `pool.swap` runs out inside the call — the 63/64 rule leaves this
    ///         frame alive to catch it — and steer the call into the catch branch.
    ///
    ///         So the catch must be reachable only when the swap genuinely
    ///         cannot succeed, never merely because the caller was stingy. Sized
    ///         well above a SwapPool swap (two SafeERC20 transfers, a mulDiv and
    ///         two storage writes measure ~90k) with room for a cold-slot worst
    ///         case; a real relayer forwards far more. Since the M-7 fix the catch
    ///         branch also only DEFERS for an unauthorised caller (see
    ///         {FALLBACK_GRACE}), so a starved call could at worst start the grace
    ///         clock — this floor keeps it from doing even that. It is checked
    ///         before the blockage test as well as before the swap, so it covers
    ///         every path that can defer (audit 2026-09-16 LOW).
    uint256 public constant MIN_DELIVER_GAS = 250_000;

    // --- governance (mirrors Gate.sol two-step ownership) ---
    address public owner;
    address public pendingOwner;

    /// @notice Low-trust incident role, mirroring the Gate/pool guardian. On the
    ///         router it can do exactly two things: release a blocked transfer's
    ///         stable to its OWN signed receiver once {FALLBACK_GRACE} has passed
    ///         (the same right the receiver has), and {cancelStableRescue}. It can
    ///         never redirect funds or move anything to itself.
    address public guardian;

    /// @notice the trusted peer router on each destination chain; the bridged
    ///         stable is sent to this address so its `finalize` can complete the
    ///         second leg. Set by the owner per corridor.
    mapping(uint256 chainIdTo => bytes remoteRouter) public remoteRouter;

    /// @notice per-submission idempotency guard for the destination leg. Set only
    ///         when the delivery actually REACHES a terminal outcome — the swap ran,
    ///         or the grace period below expired and the stable went out instead.
    mapping(bytes32 submissionId => bool) public finalized;

    /// @notice When this router first found the destination swap impossible for a
    ///         submission. Zero until that happens. See {FALLBACK_GRACE}.
    mapping(bytes32 submissionId => uint256 since) public deferredSince;

    /// @notice Stable this router is holding for transfers that were claimed out
    ///         of the Gate but have not been delivered yet (see {FALLBACK_GRACE}).
    ///
    /// @dev    Sweeping the stable while a delivery is in flight makes `finalize`
    ///         revert for the transfer while `executed` is already set on the Gate,
    ///         so the two-phase refund cannot recover it either: the funds are gone
    ///         from both ends.
    ///
    ///         This counter only knows about transfers `finalize` has SEEN and
    ///         deferred. Stable that a keeper `Gate.claim`ed straight into the
    ///         router and that nobody has called `finalize` for yet is invisible
    ///         here, and the router has no way to enumerate the Gate's claims. That
    ///         is why the stable cannot be swept by {rescue} at all: it goes through
    ///         {scheduleStableRescue} + {STABLE_RESCUE_DELAY}, a public window in
    ///         which every such transfer gets finalized (leaving) or deferred
    ///         (landing in this counter) before {executeStableRescue} computes what
    ///         is free. Every other token sweeps instantly, since only the stable is
    ///         ever held on a user's behalf.
    ///
    ///         The window does not stand alone any more (audit 2026-10-02, M7-2):
    ///         {executeStableRescue} is also held to the free balance at schedule
    ///         time LESS everything settled out since, see {stableSettledOut}. And
    ///         the keeper now `finalize`s every claim it delivers into a router, so
    ///         "every such transfer gets finalized or deferred within the window"
    ///         is something a process actually does rather than an assumption.
    uint256 public owedStable;

    /// @notice Running total of stable this router has paid out to settle
    ///         deliveries (swap input, stable intent, fallback) that were NOT
    ///         already counted in {owedStable} when the pending stable rescue was
    ///         filed. Monotonic; only its growth across a rescue's delay matters.
    ///
    /// @dev    FINDING M7-2. The M-14 cap was an AMOUNT — the free balance when the
    ///         rescue was announced — not a set of funds, and stable is fungible.
    ///         So the owner could bait it: deliver a transfer of their own into the
    ///         router (claimed, not finalized, so it reads as free), schedule a
    ///         rescue of that size, finalize the bait back out to themselves, and
    ///         48 h later sweep a VICTIM's stable that was claimed in after the
    ///         notice. The victim's `finalize` then defers for ever while the Gate
    ///         shows the transfer executed, so no refund is possible either.
    ///
    ///         Debiting the cap by every settlement since the notice closes that:
    ///         whatever counted as free at schedule time and has left since can no
    ///         longer be "replaced" by funds that arrived later. The sweep is held
    ///         to stable that was in the router when the notice went public AND
    ///         is still there — never to a later arrival, whoever it belongs to.
    ///
    ///         What remains is the case the window exists for: a transfer claimed
    ///         in BEFORE the notice that nobody finalizes for the whole 48 h. Any
    ///         `finalize` call in the window protects it (it either settles, which
    ///         debits the cap, or defers, which moves it into {owedStable}); the
    ///         keeper's finalize loop makes that call, and the guardian can
    ///         {cancelStableRescue}.
    ///
    ///         INVARIANT FOR FUTURE CODE: any new path that moves stable OUT of
    ///         the router on a user's behalf (e.g. forwarding a refunded
    ///         swap-and-bridge, H7-4) must add what it pays to this counter, or it
    ///         reopens the bait: free-at-notice stable leaves, a later arrival
    ///         refills the amount, and the sweep takes it.
    uint256 public stableSettledOut;

    /// @notice Who a refunded swap-and-bridge belongs to, and how much stable it
    ///         returns (audit 2026-10-02, H7-4).
    ///
    /// @dev    The router calls `Gate.send`, so the gate's `sentBy` is the ROUTER,
    ///         and a cancelled transfer's two-phase refund pays the stable back
    ///         into this contract, not to the user. Nothing recorded the user, so
    ///         the funds sat here (excluded from {owedStable}, refused by
    ///         {rescue}) until the owner's 48 h stable rescue, while the UI showed
    ///         "refunded". Written at send time from `msg.sender` and the exact
    ///         amount locked; {forwardRefund} pays it out once the gate shows the
    ///         refund, to this address and nowhere else.
    struct RefundClaim {
        address to;
        uint256 amount;
    }

    mapping(bytes32 submissionId => RefundClaim) public refundOf;

    /// @notice How long a blocked destination swap is retried before the router
    ///         may deliver the carrier stable instead.
    ///
    /// @dev    THE FALLBACK USED TO BE INSTANT, AND THAT WAS THE BUG.
    ///
    ///         `_deliver` wraps `pool.swap` in try/catch so funds are never
    ///         stranded. But the catch could not tell "this swap is impossible"
    ///         from "this swap is impossible *right now*": a paused pool, a token
    ///         delisted for an hour, or a `finalToken` reserve momentarily below
    ///         the required output all landed in the same branch — and because
    ///         `finalized` was set before the attempt, there was never a second
    ///         one after the condition cleared.
    ///
    ///         Two consequences, both bad. Pausing the pool during an incident
    ///         silently converted every in-flight cross-chain swap into a stable
    ///         payout, which is the opposite of what a circuit breaker is for. And
    ///         since `finalize` is PERMISSIONLESS, anyone could manufacture the
    ///         condition — swap the `finalToken` reserve below the required output,
    ///         then call `finalize` — and force the user to take the carrier asset
    ///         instead of the token they signed for, ignoring their signed
    ///         `finalMinOut` entirely. One transaction, no cost beyond the swap.
    ///
    ///         So a blocked swap DEFERS: the router records when it first saw the
    ///         blockage (`deferredSince`, set only while `_swapBlocked` holds) and
    ///         returns without settling anything. Any later call completes the real
    ///         swap the moment the condition clears.
    ///
    ///         THE WINDOW ALONE WAS NOT ENOUGH (audit M-7). `_swapBlocked` is only
    ///         evaluated at the instants `finalize` runs, and `pool.swap` is
    ///         permissionless, so an attacker could sandwich every honest
    ///         `finalize` in the window — drain the `finalToken` reserve, let the
    ///         call defer, refill in the same transaction — and, once the clock ran
    ///         out, do it one more time to trigger the fallback. Capital held per
    ///         block, not per window.
    ///
    ///         So the fallback is now also GATED BY CALLER. After the window, and
    ///         only while the swap is STILL blocked at that moment, the stable goes
    ///         out if and only if `finalize` was called by the transfer's own
    ///         `finalReceiver`, or by the router `owner`/`guardian`. Any other
    ///         caller — a keeper, an attacker — can at most complete the real swap
    ///         or keep the transfer deferred; they can never choose the user's
    ///         asset for them. The receiver does not have to act: if the blockage
    ///         clears, the next permissionless retry delivers the token they signed
    ///         for, however long ago the clock was started.
    ///
    ///         What this does and does not guarantee, honestly:
    ///           * a third party can never convert a transfer to the stable;
    ///           * a receiver (or owner/guardian) who calls `finalize` after the
    ///             window is opting in to the stable IF the swap is blocked at that
    ///             instant — and a public-mempool call can still be sandwiched into
    ///             that state. A receiver who wants the token, not the stable,
    ///             should leave the retries to the keeper or use a private relay;
    ///           * funds never strand: the owner can always release the stable to
    ///             the signed receiver after the window (never anywhere else).
    uint256 public constant FALLBACK_GRACE = 6 hours;

    /// @notice A pending owner request to sweep stranded stable. See {owedStable}
    ///         for why the stable, alone, needs a timelock.
    struct StableRescue {
        uint256 amount;
        address to;
        uint256 readyAt;
        /// @dev The free stable (balance minus {owedStable}) at SCHEDULE time —
        ///      the ceiling the execution is held to. See {executeStableRescue}
        ///      and finding M-14.
        uint256 freeAtSchedule;
        /// @dev When the notice was filed. A deferred transfer whose debt
        ///      predates this was never in `freeAtSchedule`, so settling it does
        ///      not debit the cap (M7-2).
        uint256 scheduledAt;
        /// @dev {stableSettledOut} when the notice was filed (M7-2).
        uint256 settledOutAtSchedule;
    }

    StableRescue public pendingStableRescue;

    /// @notice Delay between {scheduleStableRescue} and {executeStableRescue}.
    ///         Long enough for every keeper retry loop to have `finalize`d (or
    ///         deferred) any transfer that was claimed into the router before the
    ///         schedule became public; mirrors the Gate's GOVERNANCE_DELAY.
    uint256 public constant STABLE_RESCUE_DELAY = 48 hours;

    /// @notice A matured schedule may be executed for this long; afterwards it is
    ///         void. Without an expiry the owner could schedule once and execute
    ///         years later, when the window's "everything in flight has been seen"
    ///         argument no longer holds.
    uint256 public constant STABLE_RESCUE_WINDOW = 7 days;

    // --- events ---
    event SwapBridged(
        bytes32 indexed submissionId,
        address indexed sender,
        address tokenIn,
        uint256 amountIn,
        uint256 stableOut,
        uint256 chainIdTo,
        address finalToken,
        address finalReceiver
    );
    event Finalized(
        bytes32 indexed submissionId,
        address indexed finalReceiver,
        address finalToken,
        uint256 stableIn,
        uint256 amountOut,
        bool swapped
    );
    /// @dev the destination swap could not complete (e.g. output over the pool
    ///      lock, or token unlisted) for the whole {FALLBACK_GRACE} window; the
    ///      stable was delivered instead.
    event FinalizeFallback(bytes32 indexed submissionId, address indexed finalReceiver, uint256 stableAmount);
    /// @dev the destination swap is blocked and nothing was settled; the transfer
    ///      stays finalizable. Emitted both inside the grace window (by any caller)
    ///      and after it when the caller is not entitled to trigger the fallback.
    ///      `retryAfter` is when the stable fallback becomes available to the
    ///      receiver/owner/guardian; it may already be in the past.
    event FinalizeDeferred(
        bytes32 indexed submissionId,
        address indexed finalReceiver,
        address finalToken,
        uint256 retryAfter
    );
    event RemoteRouterSet(uint256 indexed chainIdTo, bytes remoteRouter);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event GuardianSet(address indexed guardian);
    event StableRescueScheduled(uint256 amount, address indexed to, uint256 readyAt);
    event StableRescueCancelled(address indexed by);
    event StableRescued(uint256 amount, address indexed to);
    /// @dev a refunded swap-and-bridge's stable was returned to its sender (H7-4).
    event RefundForwarded(bytes32 indexed submissionId, address indexed to, uint256 amount);

    // --- errors ---
    error NotOwner();
    /// @dev owner-or-guardian action attempted by someone else.
    error NotAuthorized();
    error ZeroAddress();
    error ZeroAmount();
    error RouteNotConfigured(uint256 chainIdTo);
    error NotDelivered(bytes32 submissionId);
    error AlreadyFinalized(bytes32 submissionId);
    error NotForThisRouter();
    error UnexpectedAsset();
    error BadReceiver();
    /// @dev the caller did not forward enough gas for the destination swap to be
    ///      attempted honestly. See {MIN_DELIVER_GAS}.
    error InsufficientGas(uint256 have, uint256 need);
    /// @dev {executeStableRescue} would have taken stable that a
    ///      claimed-but-undelivered transfer is owed. See {owedStable}.
    error RescueWouldTakeOwedFunds(uint256 requested, uint256 free);
    /// @dev {rescue} was asked for the stable; use the scheduled path.
    error StableRescueRequiresSchedule();
    error StableRescueNotScheduled();
    error StableRescueNotReady(uint256 readyAt);
    error StableRescueExpired(uint256 readyAt);
    /// @dev {forwardRefund}: this router recorded no refund for the id, or it was
    ///      already forwarded.
    error NoRefundOwed(bytes32 submissionId);
    /// @dev {forwardRefund}: the gate has not refunded the id (yet).
    error NotRefunded(bytes32 submissionId);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(Gate gate_, SwapPool pool_) {
        if (address(gate_) == address(0) || address(pool_) == address(0)) revert ZeroAddress();
        gate = gate_;
        pool = pool_;
        stable = pool_.stable();
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
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

    /// @notice Appoint (or clear) the guardian. See {guardian} for its two powers.
    function setGuardian(address newGuardian) external onlyOwner {
        guardian = newGuardian;
        emit GuardianSet(newGuardian);
    }

    /// @notice Register the peer router that receives the bridged stable on
    ///         `chainIdTo`. `router` is the raw receiver bytes the destination
    ///         Gate will decode (20 bytes for an EVM router). Pass empty to clear.
    function setRemoteRouter(uint256 chainIdTo, bytes calldata router) external onlyOwner {
        if (router.length != 0 && router.length != 20 && router.length != 32) revert BadReceiver();
        remoteRouter[chainIdTo] = router;
        emit RemoteRouterSet(chainIdTo, router);
    }

    // ---------------------------------------------------------------------
    // Source leg: swap local -> stable, then bridge with the swap intent
    // ---------------------------------------------------------------------

    /// @notice Swap `amountIn` of `tokenIn` into the stable locally, then bridge
    ///         the stable to `chainIdTo`, carrying the intent to swap it into
    ///         `finalToken` for `finalReceiver` on arrival.
    /// @param tokenIn        the local token to sell (may be the stable itself)
    /// @param amountIn       amount of `tokenIn` to pull from the caller
    /// @param minStableOut   slippage floor for the LOCAL tokenIn->stable swap
    /// @param chainIdTo      destination chain id (must have a remoteRouter set)
    /// @param finalToken     the token to receive on the destination chain
    /// @param finalReceiver  the EVM recipient on the destination chain
    /// @param finalMinOut    slippage floor for the DESTINATION stable->finalToken swap
    function swapAndBridge(
        address tokenIn,
        uint256 amountIn,
        uint256 minStableOut,
        uint256 chainIdTo,
        address finalToken,
        address finalReceiver,
        uint256 finalMinOut
    ) external nonReentrant returns (bytes32 submissionId) {
        if (amountIn == 0) revert ZeroAmount();
        if (finalToken == address(0) || finalReceiver == address(0)) revert ZeroAddress();

        bytes memory receiver = remoteRouter[chainIdTo];
        if (receiver.length == 0) revert RouteNotConfigured(chainIdTo);

        // Leg 1: acquire the stable to bridge. If the caller is already paying in
        // the stable, skip the swap and forward it directly.
        uint256 stableOut;
        if (tokenIn == stable) {
            uint256 before = IERC20(stable).balanceOf(address(this));
            IERC20(stable).safeTransferFrom(msg.sender, address(this), amountIn);
            stableOut = IERC20(stable).balanceOf(address(this)) - before;
        } else {
            IERC20(tokenIn).safeTransferFrom(msg.sender, address(this), amountIn);
            IERC20(tokenIn).forceApprove(address(pool), amountIn);
            stableOut = pool.swap(tokenIn, stable, amountIn, minStableOut, address(this));
        }
        // The gate only bridges whole multiples of the stable's bridge unit (see
        // Gate.BridgeDecimals), and a pool output is almost never one. Bridge the
        // convertible part and hand the remainder straight back to the caller,
        // rather than reverting a swap the user already priced.
        uint256 dust = stableOut % gate.bridgeUnit(stable);
        stableOut -= dust;
        if (stableOut == 0) revert ZeroAmount();
        if (dust != 0) IERC20(stable).safeTransfer(msg.sender, dust);

        // The destination intent rides in autoParams.data, which the Gate binds
        // into the submissionId (so the validators sign over it). fallbackAddress
        // mirrors finalReceiver for parity with the Gate's AutoParams shape.
        Gate.AutoParamsTo memory ap = Gate.AutoParamsTo({
            executionFee: 0,
            flags: 0,
            fallbackAddress: abi.encodePacked(finalReceiver),
            data: abi.encode(finalToken, finalReceiver, finalMinOut)
        });

        // Leg 2: bridge the stable to the peer router on the destination chain.
        IERC20(stable).forceApprove(address(gate), stableOut);
        submissionId = gate.send(stable, stableOut, chainIdTo, receiver, abi.encode(ap));
        // H7-4: if this transfer is cancelled on the destination, the gate's
        // refund pays THIS router (its `sentBy`). Record whose it is. `stableOut`
        // is a whole number of bridge units, so the refund returns exactly it.
        refundOf[submissionId] = RefundClaim({to: msg.sender, amount: stableOut});

        emit SwapBridged(
            submissionId, msg.sender, tokenIn, amountIn, stableOut, chainIdTo, finalToken, finalReceiver
        );
    }

    // ---------------------------------------------------------------------
    // Destination leg: prove delivery, then swap stable -> finalToken
    // ---------------------------------------------------------------------

    /// @notice Complete the destination swap for a bridge transfer that has
    ///         already been `claim`ed into this router. Permissionless: delivery
    ///         is proven cryptographically via `Gate.executed[submissionId]`, and
    ///         the swap intent is read back out of the same signed `autoParams`.
    ///         The bridge fields are exactly those from the source `Sent` event.
    ///
    ///         Any caller can complete the real swap or (if it is blocked) leave
    ///         the transfer deferred. Only the transfer's `finalReceiver`, the
    ///         router owner or the guardian can take the stable fallback, and only
    ///         after {FALLBACK_GRACE} while the swap is still blocked.
    /// @param bridgeDecimals the wire scale from the source `Sent` event; part of
    ///        the submissionId, so a wrong value simply fails the delivery proof.
    function finalize(
        bytes32 debridgeId,
        uint256 amount,
        uint8 bridgeDecimals,
        uint256 chainIdFrom,
        uint256 nonce,
        bytes calldata receiver,
        bytes calldata autoParams,
        bytes calldata nativeSender
    ) external nonReentrant returns (bytes32 submissionId) {
        submissionId = gate.computeSubmissionId(
            debridgeId,
            amount,
            bridgeDecimals,
            chainIdFrom,
            block.chainid,
            nonce,
            receiver,
            autoParams,
            nativeSender
        );
        // Delivery proof: the Gate only sets this after verifying the validator
        // threshold, and the amount + intent are bound into the id it signed.
        //
        // `executed` alone is NOT delivery: `Gate.cancel` also sets it, to burn a
        // stranded transfer so it can be refunded on the source chain. In that
        // case no stable ever reached this router, so settling would pay the
        // receiver out of another transfer's in-flight liquidity — while the
        // source router forwards the refund to the original sender (H7-4,
        // {forwardRefund}). Both legs must be
        // checked together.
        if (!gate.executed(submissionId) || gate.cancelled(submissionId)) {
            revert NotDelivered(submissionId);
        }
        _settle(submissionId, debridgeId, amount, receiver, autoParams);
    }

    /// @notice Convenience wrapper: `claim` the bridge transfer into this router
    ///         and complete the destination swap in one transaction.
    function claimAndFinalize(
        bytes32 debridgeId,
        uint256 amount,
        uint8 bridgeDecimals,
        uint256 chainIdFrom,
        uint256 nonce,
        bytes calldata receiver,
        bytes calldata autoParams,
        bytes calldata nativeSender,
        bytes[] calldata signatures
    ) external nonReentrant returns (bytes32 submissionId) {
        // Releases `amount` of the stable to `receiver` (this router) and sets
        // executed[submissionId]. Reverts if it was already claimed. `claim`
        // itself returns the submissionId, so there's no need to recompute it.
        submissionId = gate.claim(
            debridgeId,
            amount,
            bridgeDecimals,
            chainIdFrom,
            nonce,
            receiver,
            autoParams,
            nativeSender,
            signatures
        );
        _settle(submissionId, debridgeId, amount, receiver, autoParams);
    }

    /// @dev Shared post-delivery tail for `finalize`/`claimAndFinalize`: confirm
    ///      the stable was released to this router for an asset it knows how to
    ///      route, mark idempotent, decode the swap intent, and deliver.
    function _settle(
        bytes32 submissionId,
        bytes32 debridgeId,
        uint256 amount,
        bytes calldata receiver,
        bytes calldata autoParams
    ) internal {
        if (finalized[submissionId]) revert AlreadyFinalized(submissionId);
        // The claim released the stable to `receiver`; it must be this router,
        // and the delivered asset must be the stable we know how to route.
        if (_toAddress(receiver) != address(this)) revert NotForThisRouter();
        if (gate.tokenOf(debridgeId) != stable) revert UnexpectedAsset();
        // `amount` is the wire amount the id commits to; what the claim actually
        // released to this router is the stable's local amount.
        amount = gate.toLocalAmount(stable, amount);

        (address finalToken, address finalReceiver, uint256 finalMinOut) =
            _decodeIntent(autoParams);
        if (finalReceiver == address(0)) revert ZeroAddress();

        // The guard is set only when `_deliver` actually settles — see
        // {FALLBACK_GRACE}. Setting it before the attempt is what turned a
        // momentary blockage into a permanent downgrade to the carrier stable.
        //
        // Reentrancy is still covered: both entry points are `nonReentrant`, so
        // nothing can re-enter `_settle` while `_deliver`'s external calls are in
        // flight, and every path that moves funds sets the guard before returning.
        //
        // `deferredSince` doubles as "this submission's stable is already counted
        // in `owedStable`", which is why it is read BEFORE the call: `_deliver`
        // sets it on the first deferral, so reading after would lose the
        // distinction between an existing debt and a new one.
        uint256 owedAlready = deferredSince[submissionId];

        // Who may hand the user the stable instead of their token? Only the user
        // themself, or the router's governance — never the keeper, never a
        // stranger. See {FALLBACK_GRACE}. For `claimAndFinalize` this is the
        // claimer, which is the same rule.
        bool mayFallBack = msg.sender == finalReceiver || msg.sender == owner || msg.sender == guardian;

        if (_deliver(submissionId, amount, finalToken, finalReceiver, finalMinOut, mayFallBack)) {
            finalized[submissionId] = true;
            if (owedAlready != 0) owedStable -= amount;
            // M7-2: every settlement debits a pending rescue's cap, EXCEPT one
            // whose debt was already in `owedStable` before the notice was filed
            // — that stable was never counted free, so it cannot have been the
            // bait. Same-second deferrals are debited (the conservative side).
            uint256 scheduledAt = pendingStableRescue.scheduledAt;
            if (owedAlready == 0 || scheduledAt == 0 || owedAlready >= scheduledAt) {
                stableSettledOut += amount;
            }
        } else if (owedAlready == 0) {
            owedStable += amount;
        }
    }

    // ---------------------------------------------------------------------
    // Source leg, refunded: return the stable to the user (H7-4)
    // ---------------------------------------------------------------------

    /// @notice Pay a refunded swap-and-bridge's stable to the address that sent
    ///         it. Permissionless: the payee and amount were fixed at
    ///         {swapAndBridge}, and the refund is proven by `Gate.refunded`.
    /// @dev    The user gets the carrier stable back, not their original
    ///         `tokenIn`: the source swap already ran, and re-swapping at today's
    ///         price would hand them a different risk than the one refunded.
    function forwardRefund(bytes32 submissionId) public nonReentrant {
        _forwardRefund(submissionId);
    }

    /// @notice Run the gate's refund for a swap-and-bridge sent through this
    ///         router and forward the stable in the same transaction, so it never
    ///         rests here. Same arguments as `Gate.refund`, without `token` (it is
    ///         always the stable). Anyone may call it; the gate checks the quorum.
    function refundAndForward(
        bytes32 debridgeId,
        uint256 amount,
        uint8 bridgeDecimals,
        uint256 chainIdTo,
        uint256 nonce,
        bytes calldata receiver,
        bytes calldata autoParams,
        bytes calldata nativeSender,
        bytes[] calldata signatures
    ) external nonReentrant returns (bytes32 submissionId) {
        submissionId = gate.refund(
            stable, debridgeId, amount, bridgeDecimals, chainIdTo, nonce, receiver, autoParams, nativeSender, signatures
        );
        _forwardRefund(submissionId);
    }

    function _forwardRefund(bytes32 submissionId) internal {
        RefundClaim memory r = refundOf[submissionId];
        if (r.to == address(0)) revert NoRefundOwed(submissionId);
        if (!gate.refunded(submissionId)) revert NotRefunded(submissionId);
        delete refundOf[submissionId];
        // M7-2 invariant (see {stableSettledOut}): stable leaving on a user's
        // behalf debits a pending rescue's cap, or a later arrival could refill
        // what this took out and be swept.
        stableSettledOut += r.amount;
        IERC20(stable).safeTransfer(r.to, r.amount);
        emit RefundForwarded(submissionId, r.to, r.amount);
    }

    // ---------------------------------------------------------------------
    // Admin rescue
    // ---------------------------------------------------------------------

    /// @notice Sweep a NON-stable token stranded at the router (e.g. an asset that
    ///         is not the carrier bridged here by mistake). The router is only ever
    ///         a transient custodian, so any such balance is dust or stuck funds —
    ///         same trust model as the Gate/pool owner.
    /// @dev    Refuses the stable outright: it is the one asset the router holds on
    ///         users' behalf between `claim` and `finalize`, and the router cannot
    ///         tell which part of its balance that is. See {owedStable} and
    ///         {scheduleStableRescue}.
    function rescue(address token, uint256 amount, address to) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        if (token == stable) revert StableRescueRequiresSchedule();
        IERC20(token).safeTransfer(to, amount);
    }

    /// @notice Announce a sweep of `amount` stable to `to`, executable after
    ///         {STABLE_RESCUE_DELAY}. Re-scheduling replaces the pending request
    ///         and restarts its clock.
    /// @dev    Stable strands here only when a transfer arrives with an intent that
    ///         can never `finalize` (malformed `autoParams`, zero receiver) — that
    ///         is what this is for. Schedule the amount identified as stranded, not
    ///         the whole balance.
    /// @dev    The free balance is SNAPSHOT here and caps the payout (M-14): a
    ///         transfer that lands after this moment can never be part of the
    ///         sweep, however fat it is and however late in the window the owner
    ///         fires. See {executeStableRescue}.
    function scheduleStableRescue(uint256 amount, address to) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        uint256 readyAt = block.timestamp + STABLE_RESCUE_DELAY;
        uint256 balance = IERC20(stable).balanceOf(address(this));
        uint256 freeNow = balance > owedStable ? balance - owedStable : 0;
        if (amount > freeNow) revert RescueWouldTakeOwedFunds(amount, freeNow);
        pendingStableRescue = StableRescue({
            amount: amount,
            to: to,
            readyAt: readyAt,
            freeAtSchedule: freeNow,
            scheduledAt: block.timestamp,
            settledOutAtSchedule: stableSettledOut
        });
        emit StableRescueScheduled(amount, to, readyAt);
    }

    /// @notice Drop the pending stable sweep. Owner or guardian — the guardian is
    ///         the stop button here exactly as on the Gate.
    function cancelStableRescue() external {
        if (msg.sender != owner && msg.sender != guardian) revert NotAuthorized();
        if (pendingStableRescue.readyAt == 0) revert StableRescueNotScheduled();
        delete pendingStableRescue;
        emit StableRescueCancelled(msg.sender);
    }

    /// @notice Execute the matured stable sweep, inside
    ///         [readyAt, readyAt + {STABLE_RESCUE_WINDOW}].
    ///
    /// @dev    Pays at most the LESSER of what was free when the sweep was
    ///         announced, less every settlement since (M7-2, see
    ///         {stableSettledOut}), and what is free now.
    ///
    ///         FINDING M-14. Only the second test existed, and it is evaluated at
    ///         execution time, so everything that arrived during the delay counted
    ///         as sweepable: the owner held a matured schedule and fired it the
    ///         instant a fat transfer landed. `gate.executed[submissionId]` is
    ///         already set for that transfer, so `finalize` reverts for ever and
    ///         the two-phase refund cannot recover it either — gone from both
    ///         ends, which is precisely what {owedStable} exists to prevent. The
    ///         snapshot bounds the sweep to funds that were already stranded when
    ///         the notice became public, which is the only thing a rescue is for.
    ///
    ///         Which test actually bites: {scheduleStableRescue} already refuses
    ///         an amount larger than the free balance AT THAT MOMENT, so that is
    ///         the check that closes the hole, and it closes it early — while the
    ///         owner can still correct the figure. The snapshot here is the same
    ///         bound restated where the funds actually move, so the property
    ///         survives a future change that loosens the announcement path; on
    ///         today's code it is redundant rather than load-bearing. The live
    ///         {owedStable} test is NOT redundant: it catches stable that became
    ///         owed during the delay.
    function executeStableRescue() external onlyOwner {
        StableRescue memory r = pendingStableRescue;
        if (r.readyAt == 0) revert StableRescueNotScheduled();
        if (block.timestamp < r.readyAt) revert StableRescueNotReady(r.readyAt);
        if (block.timestamp > r.readyAt + STABLE_RESCUE_WINDOW) revert StableRescueExpired(r.readyAt);
        delete pendingStableRescue;

        uint256 balance = IERC20(stable).balanceOf(address(this));
        uint256 free = balance > owedStable ? balance - owedStable : 0;
        // M7-2: what was free at the notice, minus what has been settled out of
        // the router since. Without the debit, stable the owner counted as free
        // (their own claimed-but-unfinalized bait) could leave via `finalize` and
        // a later victim's delivery would refill the "free" amount.
        uint256 settledSince = stableSettledOut - r.settledOutAtSchedule;
        uint256 stillFree = r.freeAtSchedule > settledSince ? r.freeAtSchedule - settledSince : 0;
        if (stillFree < free) free = stillFree;
        if (r.amount > free) revert RescueWouldTakeOwedFunds(r.amount, free);

        IERC20(stable).safeTransfer(r.to, r.amount);
        emit StableRescued(r.amount, r.to);
    }

    // ---------------------------------------------------------------------
    // Internal
    // ---------------------------------------------------------------------

    /// @dev Swap the delivered stable into `finalToken` for `finalReceiver`.
    ///
    ///      Returns TRUE when the delivery reached a terminal outcome (the swap
    ///      ran, or the stable went out because {FALLBACK_GRACE} expired and the
    ///      caller was entitled to it) and the caller should mark the submission
    ///      finalized. Returns FALSE when the swap is only *currently* impossible
    ///      or the caller may not take the fallback: nothing is settled, the stable
    ///      stays at the router, and any later `finalize` completes it properly.
    function _deliver(
        bytes32 submissionId,
        uint256 amount,
        address finalToken,
        address finalReceiver,
        uint256 finalMinOut,
        bool mayFallBack
    ) internal returns (bool settled) {
        // Degenerate intent: the caller wanted the stable itself on this chain.
        if (finalToken == stable) {
            IERC20(stable).safeTransfer(finalReceiver, amount);
            emit Finalized(submissionId, finalReceiver, finalToken, amount, amount, false);
            return true;
        }

        // Refuse to even LOOK at the swap without enough gas to complete it. Both
        // ways out of here can start the grace clock — `_swapBlocked` (whose
        // `quote` try/catch reads any revert, out-of-gas included, as "blocked")
        // and the swap's own catch — so the floor must precede both, or a starved
        // call defers a transfer the floor exists to protect. Not at function
        // entry: the degenerate stable intent above starts no clock.
        if (gasleft() < MIN_DELIVER_GAS) revert InsufficientGas(gasleft(), MIN_DELIVER_GAS);

        // Is the swap blocked *at this instant*? Every condition tested there can
        // clear on its own, so a blockage is a reason to come back, not a reason to
        // hand the user a different asset than the one they signed for.
        if (_swapBlocked(finalToken, amount, finalMinOut)) {
            return _deferOrFallBack(submissionId, amount, finalToken, finalReceiver, mayFallBack);
        }

        // And again for the swap itself, so the catch below can only ever mean
        // "this swap is impossible", never "the caller starved it" — the blockage
        // check above spent some of what the first test saw.
        if (gasleft() < MIN_DELIVER_GAS) revert InsufficientGas(gasleft(), MIN_DELIVER_GAS);

        IERC20(stable).forceApprove(address(pool), amount);
        try pool.swap(stable, finalToken, amount, finalMinOut, finalReceiver) returns (uint256 out) {
            emit Finalized(submissionId, finalReceiver, finalToken, amount, out, true);
            return true;
        } catch {
            // `_swapBlocked` said this should work, so a revert here is something
            // it does not model (a hostile finalToken, an unexpected pool state).
            // It used to settle to the stable on the spot; that made the catch a
            // second, unguarded route to the fallback, so it now obeys the same
            // window and caller rule as a modelled blockage.
            IERC20(stable).forceApprove(address(pool), 0);
            return _deferOrFallBack(submissionId, amount, finalToken, finalReceiver, mayFallBack);
        }
    }

    /// @dev The swap cannot run right now. Start (never restart) the grace clock;
    ///      then either keep the transfer deferred, or — only once the window has
    ///      passed AND the caller is the receiver/owner/guardian — deliver the
    ///      stable. Both conditions are re-evaluated here, at the moment of the
    ///      fallback, against the blockage the caller just observed.
    function _deferOrFallBack(
        bytes32 submissionId,
        uint256 amount,
        address finalToken,
        address finalReceiver,
        bool mayFallBack
    ) internal returns (bool settled) {
        uint256 since = deferredSince[submissionId];
        if (since == 0) {
            since = block.timestamp;
            deferredSince[submissionId] = since;
        }
        uint256 retryAfter = since + FALLBACK_GRACE;
        if (block.timestamp < retryAfter || !mayFallBack) {
            emit FinalizeDeferred(submissionId, finalReceiver, finalToken, retryAfter);
            return false;
        }
        // The window has passed, the swap is still impossible, and the user (or
        // governance on their behalf) asked for the stable rather than wait
        // longer. Deliver it — the original never-strand guarantee, reached only
        // after the condition proved durable and only at the receiver's own hand.
        IERC20(stable).safeTransfer(finalReceiver, amount);
        emit FinalizeFallback(submissionId, finalReceiver, amount);
        return true;
    }

    /// @dev Would `pool.swap` fail right now for a reason that can clear later?
    ///
    ///      All four are recoverable states, which is exactly why they must not
    ///      trigger the stable fallback on sight:
    ///        * the pool is paused (an incident ends);
    ///        * `finalToken` is not listed (a delisting can be reversed);
    ///        * the output would exceed the pool's lock for `finalToken` (the
    ///          reserve is refilled, or another swap stops draining it) — and this
    ///          is the one an attacker can manufacture on demand;
    ///        * the output is under the user's own signed `finalMinOut` (prices
    ///          move, and honouring that floor is the entire point of signing it).
    ///
    ///      `quote` reverts for an unlisted token, so the try/catch also covers the
    ///      stable itself being somehow unquotable.
    function _swapBlocked(address finalToken, uint256 amount, uint256 finalMinOut)
        internal
        view
        returns (bool)
    {
        if (pool.paused()) return true;
        (bool listed,,, uint256 reserve) = pool.tokens(finalToken);
        if (!listed) return true;
        try pool.quote(stable, finalToken, amount) returns (uint256 out) {
            return out == 0 || out < finalMinOut || out > reserve;
        } catch {
            return true;
        }
    }

    /// @dev Read (finalToken, finalReceiver, finalMinOut) back out of the signed
    ///      Gate.AutoParamsTo.data. Reverts if the payload is malformed.
    function _decodeIntent(bytes calldata autoParams)
        internal
        pure
        returns (address finalToken, address finalReceiver, uint256 finalMinOut)
    {
        Gate.AutoParamsTo memory ap = abi.decode(autoParams, (Gate.AutoParamsTo));
        (finalToken, finalReceiver, finalMinOut) = abi.decode(ap.data, (address, address, uint256));
    }

    /// @dev Decode `receiver` as an EVM address, exactly as the Gate does — and
    ///      exactly as strictly: 20 bytes and no other width. `_settle` compares
    ///      the result against `address(this)` to prove the transfer was routed
    ///      here, so a looser decode here than in the Gate would let a padded
    ///      receiver satisfy that check on a width the Gate itself refuses. Keep
    ///      the two in lockstep.
    function _toAddress(bytes calldata receiver) internal pure returns (address addr) {
        if (receiver.length != 20) revert BadReceiver();
        addr = address(bytes20(receiver[0:20]));
    }
}
