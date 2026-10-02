// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {SwapPool} from "../src/SwapPool.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

/// @dev ERC-20 with configurable decimals (to exercise the swap's decimal
///      normalisation — e.g. a 6-dec stablecoin against 18-dec tokens).
contract MockERC20 is ERC20 {
    uint8 private immutable _dec;

    constructor(string memory n, string memory s, uint8 d) ERC20(n, s) {
        _dec = d;
    }

    function decimals() public view override returns (uint8) {
        return _dec;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @dev A token whose `transfer` reenters `SwapPool.swap` once, to prove the
///      nonReentrant guard blocks reentrancy on the outgoing leg.
contract ReenterToken is ERC20 {
    SwapPool public pool;
    address public tokenIn;
    bool public entered;

    constructor() ERC20("Re", "RE") {}

    function decimals() public pure override returns (uint8) {
        return 18;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function arm(SwapPool p, address tokenIn_) external {
        pool = p;
        tokenIn = tokenIn_;
    }

    function transfer(address to, uint256 amount) public override returns (bool) {
        if (address(pool) != address(0) && !entered) {
            entered = true;
            // reenter — must hit the ReentrancyGuard and revert the whole swap
            pool.swap(tokenIn, address(this), 1, 0, address(this));
        }
        return super.transfer(to, amount);
    }
}

contract SwapTest is Test {
    SwapPool pool;

    MockERC20 usd; // stable, 6 decimals, price 1.0
    MockERC20 weth; // 18 decimals, price 3180
    MockERC20 tt; // 18 decimals, price 1.0

    address user = address(0x115E7);
    address oracle = address(0x0AC1E);
    address guardian = address(0x6A5D);
    address attacker = address(0xBAD);

    uint256 constant PRICE_ONE = 1e18;
    uint16 constant DEVIATION = 1000; // 10%

    uint256 constant WETH_PRICE = 3180e18;
    uint256 constant TT_PRICE = 1e18;

    function setUp() public {
        usd = new MockERC20("Mock USD", "mUSD", 6);
        weth = new MockERC20("Wrapped Ether", "WETH", 18);
        tt = new MockERC20("Test Token", "TT", 18);

        pool = new SwapPool(address(usd), DEVIATION);
        pool.setOracle(oracle);

        pool.listToken(address(weth), WETH_PRICE);
        pool.listToken(address(tt), TT_PRICE);

        // Seed reserves (the locks).
        _seed(usd, 1_000_000e6); // 1,000,000 mUSD
        _seed(weth, 100e18); // 100 WETH
        _seed(tt, 500_000e18); // 500,000 TT
    }

    function _seed(MockERC20 token, uint256 amount) internal {
        token.mint(address(this), amount);
        token.approve(address(pool), amount);
        pool.seedLiquidity(address(token), amount);
    }

    function _fund(MockERC20 token, address who, uint256 amount) internal {
        token.mint(who, amount);
        vm.prank(who);
        token.approve(address(pool), type(uint256).max);
    }

    // ----------------------------------------------------------------- quote

    function test_Quote_MixedDecimals() public view {
        // 1 WETH -> mUSD == 3180.000000
        assertEq(pool.quote(address(weth), address(usd), 1e18), 3180e6);
        // 3180 mUSD -> 1 WETH
        assertEq(pool.quote(address(usd), address(weth), 3180e6), 1e18);
        // 1 WETH -> TT == 3180 TT (both 18-dec)
        assertEq(pool.quote(address(weth), address(tt), 1e18), 3180e18);
    }

    // ----------------------------------------------------------------- swaps

    function test_Swap_TokenToStable() public {
        _fund(weth, user, 1e18);
        vm.prank(user);
        uint256 out = pool.swap(address(weth), address(usd), 1e18, 0, user);
        assertEq(out, 3180e6);
        assertEq(usd.balanceOf(user), 3180e6);
        (,, , uint256 wReserve) = _info(address(weth));
        assertEq(wReserve, 101e18); // 100 + 1
        (,, , uint256 uReserve) = _info(address(usd));
        assertEq(uReserve, 1_000_000e6 - 3180e6);
    }

    function test_Swap_StableToToken() public {
        _fund(usd, user, 3180e6);
        vm.prank(user);
        uint256 out = pool.swap(address(usd), address(weth), 3180e6, 0, user);
        assertEq(out, 1e18);
        assertEq(weth.balanceOf(user), 1e18);
    }

    function test_Swap_TokenToToken() public {
        _fund(weth, user, 1e18);
        vm.prank(user);
        uint256 out = pool.swap(address(weth), address(tt), 1e18, 0, user);
        assertEq(out, 3180e18);
        assertEq(tt.balanceOf(user), 3180e18);
    }

    // --------------------------------------------------------- the lock / cap

    function test_Swap_ExceedsLock_Reverts() public {
        // buying 100.01 WETH needs > 100 WETH reserve -> ExceedsLock
        uint256 amountIn = 318032e6; // 318,032 mUSD -> ~100.01 WETH
        _fund(usd, user, amountIn);
        uint256 out = pool.quote(address(usd), address(weth), amountIn);
        assertGt(out, 100e18);
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(SwapPool.ExceedsLock.selector, out, 100e18));
        pool.swap(address(usd), address(weth), amountIn, 0, user);
    }

    function test_Swap_AtLockBoundary_Succeeds() public {
        // buying exactly 100 WETH (== reserve) must succeed and zero the reserve
        uint256 amountIn = 318_000e6; // 318,000 mUSD -> exactly 100 WETH
        _fund(usd, user, amountIn);
        vm.prank(user);
        uint256 out = pool.swap(address(usd), address(weth), amountIn, 0, user);
        assertEq(out, 100e18);
        (,, , uint256 wReserve) = _info(address(weth));
        assertEq(wReserve, 0);

        // now the pool is dry for WETH — any further WETH buy reverts
        _fund(usd, attacker, 3180e6);
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(SwapPool.ExceedsLock.selector, 1e18, 0));
        pool.swap(address(usd), address(weth), 3180e6, 0, attacker);
    }

    // ------------------------------------------------------------- slippage

    function test_Swap_Slippage_Reverts() public {
        _fund(weth, user, 1e18);
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(SwapPool.Slippage.selector, 3180e6, 3181e6));
        pool.swap(address(weth), address(usd), 1e18, 3181e6, user);
    }

    // ------------------------------------------------- rounding favors pool

    function test_Swap_RoundTrip_NeverProfits() public {
        // TT (18-dec) -> mUSD (6-dec) loses sub-1e-6 dust; round-trip <= input.
        uint256 amountIn = 1e18 + 5e11; // 1.0000005 TT
        _fund(tt, user, amountIn);

        vm.startPrank(user);
        uint256 got = pool.swap(address(tt), address(usd), amountIn, 0, user);
        usd.approve(address(pool), got);
        uint256 back = pool.swap(address(usd), address(tt), got, 0, user);
        vm.stopPrank();

        assertLe(back, amountIn, "round-trip must not create value");
        assertLt(back, amountIn, "the 6-dec hop should drop dust");
        assertEq(back, 1e18);
    }

    // ------------------------------------------------------------- pricing

    function test_SetPrice_OracleWithinDeviation() public {
        // M7-3: a step is capped by the fee as well; open the fee to the 10% cap
        // so this test exercises the deviation cap and the cooldown alone.
        pool.setFee(DEVIATION);
        vm.prank(oracle);
        pool.setPrice(address(weth), WETH_PRICE, 3498e18); // +10%, exactly at the cap
        (, , uint256 price, ) = _info(address(weth));
        assertEq(price, 3498e18);
    }

    function test_SetPrice_RevertsDeviationTooHigh() public {
        // M7-3: a step is capped by the fee as well; open the fee to the 10% cap
        // so this test exercises the deviation cap and the cooldown alone.
        pool.setFee(DEVIATION);
        vm.prank(oracle);
        vm.expectRevert(
            abi.encodeWithSelector(SwapPool.PriceDeviationTooHigh.selector, 3180e18, 3600e18, DEVIATION)
        );
        pool.setPrice(address(weth), WETH_PRICE, 3600e18); // +13.2% > 10%
    }

    function test_SetPrice_OnlyOracle() public {
        vm.prank(attacker);
        vm.expectRevert(SwapPool.NotOracle.selector);
        pool.setPrice(address(weth), WETH_PRICE, 3200e18);
    }

    function test_SetPrice_StableForbidden() public {
        vm.prank(oracle);
        vm.expectRevert(SwapPool.StableRepriceForbidden.selector);
        pool.setPrice(address(usd), PRICE_ONE, 2e18);
    }

    function test_SetPrice_CooldownBoundsRateOfChange() public {
        // M7-3: a step is capped by the fee as well; open the fee to the 10% cap
        // so this test exercises the deviation cap and the cooldown alone.
        pool.setFee(DEVIATION);
        // The first repricing after listing is free.
        vm.prank(oracle);
        pool.setPrice(address(weth), WETH_PRICE, 3300e18); // +~3.8%, within the 10% cap

        // A second repricing before the cooldown elapses is rejected — so a
        // compromised oracle cannot chain several capped steps in one block and
        // walk the price arbitrarily.
        uint256 nextAllowed = block.timestamp + pool.minPriceUpdateInterval();
        vm.prank(oracle);
        vm.expectRevert(
            abi.encodeWithSelector(SwapPool.PriceUpdateTooSoon.selector, address(weth), nextAllowed)
        );
        pool.setPrice(address(weth), 3300e18, 3400e18);

        // Price is unchanged from the single allowed step.
        (, , uint256 price, ) = _info(address(weth));
        assertEq(price, 3300e18);

        // After the cooldown, one more capped step is allowed.
        vm.warp(nextAllowed);
        vm.prank(oracle);
        pool.setPrice(address(weth), 3300e18, 3400e18);
        (, , price, ) = _info(address(weth));
        assertEq(price, 3400e18);
    }

    function test_SetMinPriceUpdateInterval_OnlyOwner() public {
        vm.prank(attacker);
        vm.expectRevert(SwapPool.NotOwner.selector);
        pool.setMinPriceUpdateInterval(0);
    }

    // ----------------------------------------------------------------- fees

    function test_Fee_ReducesOutput() public {
        pool.setFee(100); // 1%
        // 1 WETH -> mUSD: 3180 * 0.99 = 3148.2
        assertEq(pool.quote(address(weth), address(usd), 1e18), 3148_200000);
        _fund(weth, user, 1e18);
        vm.prank(user);
        uint256 out = pool.swap(address(weth), address(usd), 1e18, 0, user);
        assertEq(out, 3148_200000);
    }

    function test_SetFee_TooHigh() public {
        vm.expectRevert(SwapPool.FeeTooHigh.selector);
        pool.setFee(1001);
    }

    function test_SetFee_OnlyOwner() public {
        vm.prank(attacker);
        vm.expectRevert(SwapPool.NotOwner.selector);
        pool.setFee(50);
    }

    // -------------------------------------------------------------- pausing

    function test_Pause_HaltsSwap() public {
        _fund(weth, user, 1e18);
        pool.pause();
        vm.prank(user);
        vm.expectRevert(SwapPool.EnforcedPause.selector);
        pool.swap(address(weth), address(usd), 1e18, 0, user);
    }

    function test_Guardian_CanPauseNotUnpause() public {
        pool.setGuardian(guardian);
        vm.prank(guardian);
        pool.pause();
        assertTrue(pool.paused());

        vm.prank(guardian);
        vm.expectRevert(SwapPool.NotOwner.selector);
        pool.unpause();

        pool.unpause();
        assertFalse(pool.paused());
    }

    function test_Pause_OnlyOwnerOrGuardian() public {
        vm.prank(attacker);
        vm.expectRevert(SwapPool.NotAuthorizedToPause.selector);
        pool.pause();
    }

    // ---------------------------------------------------------- reentrancy

    function test_Swap_ReentrancyBlocked() public {
        ReenterToken re = new ReenterToken();
        pool.listToken(address(re), 1e18);
        re.mint(address(this), 1000e18);
        re.approve(address(pool), type(uint256).max);
        pool.seedLiquidity(address(re), 1000e18);
        re.arm(pool, address(usd));

        _fund(usd, user, 100e6);
        vm.prank(user);
        // the outgoing transfer of `re` reenters swap() -> guard reverts the tx
        vm.expectRevert();
        pool.swap(address(usd), address(re), 100e6, 0, user);
    }

    // ------------------------------------------------------- access control

    function test_ListToken_OnlyOwner() public {
        MockERC20 x = new MockERC20("X", "X", 18);
        vm.prank(attacker);
        vm.expectRevert(SwapPool.NotOwner.selector);
        pool.listToken(address(x), 1e18);
    }

    function test_ListToken_AlreadyListed() public {
        vm.expectRevert(abi.encodeWithSelector(SwapPool.TokenAlreadyListed.selector, address(weth)));
        pool.listToken(address(weth), 1e18);
    }

    function test_ListToken_StableAlreadyListed() public {
        vm.expectRevert(abi.encodeWithSelector(SwapPool.TokenAlreadyListed.selector, address(usd)));
        pool.listToken(address(usd), 1e18);
    }

    function test_SeedAndWithdraw_OnlyOwner() public {
        vm.startPrank(attacker);
        vm.expectRevert(SwapPool.NotOwner.selector);
        pool.seedLiquidity(address(weth), 1e18);
        vm.expectRevert(SwapPool.NotOwner.selector);
        pool.withdrawLiquidity(address(weth), 1e18, attacker);
        vm.stopPrank();
    }

    function test_Withdraw_ExceedsReserve() public {
        vm.expectRevert(abi.encodeWithSelector(SwapPool.ExceedsLock.selector, 101e18, 100e18));
        pool.withdrawLiquidity(address(weth), 101e18, address(this));
    }

    function test_Delist_RequiresZeroReserve() public {
        vm.expectRevert(SwapPool.ReserveNonZero.selector);
        pool.delistToken(address(weth));

        pool.withdrawLiquidity(address(weth), 100e18, address(this));
        pool.delistToken(address(weth));
        (bool listed,,,) = _info(address(weth));
        assertFalse(listed);
    }

    /// L-2: the repricing clock belongs to the listing, so delisting must clear
    /// it. `setPrice` exempts the FIRST update after a listing via `last == 0`; a
    /// stale timestamp surviving into a re-listing would revoke that exemption and
    /// freeze the new token's price behind a cooldown it never earned.
    function test_Delist_ClearsThePriceClock_SoARelistCanPriceFreely() public {
        // M7-3: a step is capped by the fee as well; open the fee to the 10% cap
        // so this test exercises the deviation cap and the cooldown alone.
        pool.setFee(DEVIATION);
        // Reprice once so the clock is set, then fully unwind and delist.
        vm.prank(oracle);
        pool.setPrice(address(weth), WETH_PRICE, 3200e18);
        assertGt(pool.lastPriceUpdate(address(weth)), 0, "clock should be set");

        pool.withdrawLiquidity(address(weth), 100e18, address(this));
        pool.delistToken(address(weth));
        assertEq(pool.lastPriceUpdate(address(weth)), 0, "delist must clear the clock");

        // Re-list and immediately reprice: the first update after a listing is
        // always allowed, and must stay allowed here.
        pool.listToken(address(weth), 3000e18);
        vm.prank(oracle);
        pool.setPrice(address(weth), 3000e18, 3100e18);
        (,, uint256 price,) = _info(address(weth));
        assertEq(price, 3100e18, "a re-listed token must be freely pricable");
    }

    /// The stable's price is the pool's unit of account and `setPrice` refuses to
    /// move it — but delisting was the way around that: drain the reserve, delist,
    /// re-list at any price at all, never touching `setPrice`. The cross-chain
    /// SwapRouter's accounting rests on that peg, so the hatch has to be shut.
    function test_Delist_StableIsForbidden() public {
        pool.withdrawLiquidity(address(usd), 1_000_000e6, address(this));
        (,,, uint256 reserve) = _info(address(usd));
        assertEq(reserve, 0, "premise: the owner can drain the stable's reserve");

        vm.expectRevert(SwapPool.StableDelistForbidden.selector);
        pool.delistToken(address(usd));

        (bool listed,, uint256 price,) = _info(address(usd));
        assertTrue(listed, "the stable must stay listed");
        assertEq(price, PRICE_ONE, "the stable's price must stay pinned");
    }

    /// Re-listing is a reprice, so it obeys the same deviation cap `setPrice`
    /// does. Otherwise delist -> relist walked any token to any price in one
    /// transaction, around both the cap and the cooldown — which would make the
    /// documented rate limit a constraint on the oracle only, never on the owner.
    function test_Relist_IsBoundedByTheDeviationCap() public {
        pool.withdrawLiquidity(address(weth), 100e18, address(this));
        pool.delistToken(address(weth));

        // WETH_PRICE is 3180; the cap is 10%, so 1 wei over 3498 must revert.
        uint256 tooHigh = WETH_PRICE + Math.mulDiv(WETH_PRICE, DEVIATION, 10_000) + 1;
        vm.expectRevert(
            abi.encodeWithSelector(
                SwapPool.PriceDeviationTooHigh.selector, WETH_PRICE, tooHigh, DEVIATION
            )
        );
        pool.listToken(address(weth), tooHigh);

        // ...and the same move one wei inside the cap is still allowed.
        pool.listToken(address(weth), tooHigh - 1);
        (,, uint256 price,) = _info(address(weth));
        assertEq(price, tooHigh - 1);
    }

    /// A token this pool has never seen has no remembered price, so its first
    /// listing is unconstrained — the cap needs something to measure against.
    function test_FirstListing_IsUnconstrained() public {
        MockERC20 fresh = new MockERC20("Fresh", "FR", 18);
        pool.listToken(address(fresh), 999_999e18);
        (bool listed,, uint256 price,) = _info(address(fresh));
        assertTrue(listed);
        assertEq(price, 999_999e18);
    }

    function test_MaxSwapOut() public view {
        (uint256 reserve, uint256 usdValue) = pool.maxSwapOut(address(weth));
        assertEq(reserve, 100e18);
        assertEq(usdValue, 318_000e18); // 100 WETH * 3180 = 318,000 USD (1e18-scaled)
    }

    // ----------------------------------------------------------- ownership

    function test_TransferOwnership_TwoStep() public {
        address newOwner = address(0xBEEF);
        pool.transferOwnership(newOwner);
        assertEq(pool.owner(), address(this));
        vm.prank(newOwner);
        pool.acceptOwnership();
        assertEq(pool.owner(), newOwner);
    }

    // helper: unpack the public mapping getter
    function _info(address token)
        internal
        view
        returns (bool listed, uint8 dec, uint256 price, uint256 reserve)
    {
        (listed, dec, price, reserve) = pool.tokens(token);
    }

    // ------------------------------------------------------------------
    // Price staleness (the rate limits bound speed, not age)
    // ------------------------------------------------------------------

    /// THE regression. `maxPriceDeviationBps` and `minPriceUpdateInterval` bound
    /// how fast a price may MOVE. Neither bounds how OLD it may be, and `swap`
    /// never read `lastPriceUpdate` at all — so a stalled oracle kept quoting its
    /// last figure forever and every swap against it was arbitrage, running until
    /// the output reserve hit the lock.
    function test_Swap_RefusesAStalePrice() public {
        uint256 age = pool.maxPriceAge();
        assertGt(age, 0, "a staleness bound must be on by default");

        _fund(usd, user, 10_000e6);

        // Just inside the window: still tradeable.
        vm.warp(block.timestamp + age);
        vm.prank(user);
        pool.swap(address(usd), address(weth), 1_000e6, 0, user);

        // One second past it: the pool stops rather than trades at a price the
        // oracle has stopped confirming.
        vm.warp(block.timestamp + 1);
        vm.startPrank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                SwapPool.StalePrice.selector, address(weth), pool.priceSetAt(address(weth)), age
            )
        );
        pool.swap(address(usd), address(weth), 1_000e6, 0, user);
        vm.stopPrank();
    }

    /// Either side going stale misprices the pair, so both are checked — it is the
    /// OUTPUT side an arbitrageur drains, but a stale input is equally wrong.
    function test_Swap_ChecksBothSidesForStaleness() public {
        _fund(weth, user, 10e18);
        vm.warp(block.timestamp + pool.maxPriceAge() + 1);
        vm.startPrank(user);
        vm.expectRevert(); // weth stale, whichever direction it is quoted in
        pool.swap(address(weth), address(usd), 1e18, 0, user);
        vm.stopPrank();
    }

    /// A quote is what callers act on (SwapRouter reads it to decide whether a
    /// swap is possible right now), so it must refuse a stale price too.
    function test_Quote_RefusesAStalePrice() public {
        vm.warp(block.timestamp + pool.maxPriceAge() + 1);
        vm.expectRevert();
        pool.quote(address(usd), address(weth), 1_000e6);
    }

    /// A refreshed price re-opens the pool — the guard stops a DEAD feed, not a
    /// live one.
    function test_Swap_ResumesOnceTheOracleRefreshes() public {
        _fund(usd, user, 10_000e6);
        vm.warp(block.timestamp + pool.maxPriceAge() + 1);
        vm.prank(oracle);
        pool.setPrice(address(weth), WETH_PRICE, 3180e18);

        vm.prank(user);
        pool.swap(address(usd), address(weth), 1_000e6, 0, user);
    }

    /// The stable is exempt: its price is PRICE_ONE by construction and `setPrice`
    /// refuses to move it, so there is no feed that could go stale. A stable-only
    /// pair must keep working however long the oracle has been quiet.
    function test_Swap_TheStableIsNeverStale() public {
        _fund(usd, user, 10_000e6);

        // `tt` is repriced so only the stable's own age is in question.
        vm.warp(block.timestamp + pool.maxPriceAge() * 3);
        vm.prank(oracle);
        pool.setPrice(address(tt), TT_PRICE, 1e18);

        vm.prank(user);
        pool.swap(address(usd), address(tt), 100e6, 0, user);
    }

    /// A freshly listed token is fresh. `lastPriceUpdate` stays zero until the
    /// first repricing (so that repricing is free), so the staleness clock needs
    /// its own stamp or every new listing would be born unswappable.
    function test_ListToken_StartsTheStalenessClock() public {
        MockERC20 nt = new MockERC20("New", "NEW", 18);
        pool.listToken(address(nt), 5e18);
        assertEq(pool.priceSetAt(address(nt)), block.timestamp, "clock not started at listing");
        assertEq(pool.lastPriceUpdate(address(nt)), 0, "the first reprice must still be free");

        nt.mint(address(this), 1_000e18);
        nt.approve(address(pool), 1_000e18);
        pool.seedLiquidity(address(nt), 1_000e18);
        _fund(usd, user, 10_000e6);

        vm.prank(user);
        pool.swap(address(usd), address(nt), 100e6, 0, user); // must not revert
    }

    function test_SetMaxPriceAge_OnlyOwner() public {
        vm.prank(attacker);
        vm.expectRevert(SwapPool.NotOwner.selector);
        pool.setMaxPriceAge(1 hours);
    }

    /// Zero disables the check, for dev chains — the same escape hatch
    /// `minPriceUpdateInterval` has, and the same warning attached to it.
    function test_SetMaxPriceAge_ZeroDisablesTheCheck() public {
        _fund(usd, user, 10_000e6);
        pool.setMaxPriceAge(0);
        vm.warp(block.timestamp + 3650 days);
        vm.prank(user);
        pool.swap(address(usd), address(weth), 1_000e6, 0, user);
    }

    // ------------------------------------------- M7-3: sandwiching an update

    /// The audit PoC, as it used to run: fee 0, 200k mUSD into WETH, the
    /// oracle's predictable +10% step, WETH back out for ~220k. Now a fee-0 pool
    /// cannot move its price at all (it can still re-assert it), so the update
    /// the sandwich needs never happens.
    function test_M7_3_AFeeZeroPoolCannotMoveItsPrice() public {
        assertEq(pool.feeBps(), 0);
        assertEq(pool.priceStepCapBps(), 0);
        vm.prank(oracle);
        vm.expectRevert(abi.encodeWithSelector(SwapPool.PriceDeviationTooHigh.selector, WETH_PRICE, 3498e18, uint16(0)));
        pool.setPrice(address(weth), WETH_PRICE, 3498e18);

        // Re-asserting the same price (the staleness refresh) still works.
        vm.prank(oracle);
        pool.setPrice(address(weth), WETH_PRICE, WETH_PRICE);
    }

    /// With a fee, the step is capped at the fee — and the PoC's round trip at
    /// the largest allowed step now LOSES money, in both directions.
    function test_M7_3_ARoundTripAroundTheLargestStepIsUnprofitable() public {
        pool.setFee(100); // 1%
        assertEq(pool.priceStepCapBps(), 100, "the step cap is the lesser of fee and deviation");

        // The audit's +10% step is refused outright.
        vm.prank(oracle);
        vm.expectRevert(abi.encodeWithSelector(SwapPool.PriceDeviationTooHigh.selector, WETH_PRICE, 3498e18, uint16(100)));
        pool.setPrice(address(weth), WETH_PRICE, 3498e18);

        // Up: 200k in before a +1% step, everything out after it.
        uint256 capital = 200_000e6;
        _fund(usd, attacker, capital);
        _fund(weth, attacker, 0);
        uint256 snap = vm.snapshotState();
        vm.prank(attacker);
        uint256 wethGot = pool.swap(address(usd), address(weth), capital, 0, attacker);
        vm.prank(oracle);
        pool.setPrice(address(weth), WETH_PRICE, 3211_8e17); // +1%, exactly the cap
        vm.prank(attacker);
        uint256 usdBack = pool.swap(address(weth), address(usd), wethGot, 0, attacker);
        assertLt(usdBack, capital, "sandwiching an up-step must lose");

        // Down: sell 50 WETH before a -1% step, buy it back after.
        vm.revertToState(snap);
        _fund(weth, attacker, 50e18);
        vm.prank(attacker);
        uint256 usdGot = pool.swap(address(weth), address(usd), 50e18, 0, attacker);
        vm.prank(oracle);
        pool.setPrice(address(weth), WETH_PRICE, 3148_2e17); // -1%, exactly the cap
        vm.prank(attacker);
        uint256 wethBack = pool.swap(address(usd), address(weth), usdGot, 0, attacker);
        assertLt(wethBack, 50e18, "sandwiching a down-step must lose");
    }

    /// The invariant itself, over fee, capital and direction: at any step the
    /// pool accepts, a round trip around it never returns more than it put in.
    function testFuzz_M7_3_NoRoundTripAroundOneUpdateProfits(uint16 fee, uint256 capital, bool up) public {
        fee = uint16(bound(fee, 1, 1000));
        pool.setFee(fee);
        uint256 step = Math.mulDiv(WETH_PRICE, pool.priceStepCapBps(), 10_000);
        uint256 newPrice = up ? WETH_PRICE + step : WETH_PRICE - step;
        if (up) {
            capital = bound(capital, 1e6, 250_000e6);
            _fund(usd, attacker, capital);
            vm.prank(attacker);
            uint256 got = pool.swap(address(usd), address(weth), capital, 0, attacker);
            vm.prank(oracle);
            pool.setPrice(address(weth), WETH_PRICE, newPrice);
            _fund(weth, attacker, 0);
            vm.prank(attacker);
            uint256 back = pool.swap(address(weth), address(usd), got, 0, attacker);
            assertLe(back, capital);
        } else {
            capital = bound(capital, 1e15, 80e18);
            _fund(weth, attacker, capital);
            vm.prank(attacker);
            uint256 got = pool.swap(address(weth), address(usd), capital, 0, attacker);
            vm.prank(oracle);
            pool.setPrice(address(weth), WETH_PRICE, newPrice);
            _fund(usd, attacker, 0);
            vm.prank(attacker);
            uint256 back = pool.swap(address(usd), address(weth), got, 0, attacker);
            assertLe(back, capital);
        }
    }

    /// Lowering the fee lowers the step cap with it, live.
    function test_M7_3_TheStepCapFollowsTheFee() public {
        pool.setFee(1000);
        assertEq(pool.priceStepCapBps(), DEVIATION);
        pool.setMaxPriceDeviation(300);
        assertEq(pool.priceStepCapBps(), 300, "deviation below the fee wins");
        pool.setFee(30);
        assertEq(pool.priceStepCapBps(), 30, "fee below the deviation wins");
    }

    // ----------------------------------- M7-4: compare-and-set on the price

    /// A price-keeper fed a false on-chain price by its RPC plans its step from
    /// that figure. The step only lands if the figure is the real one.
    function test_M7_4_SetPriceRefusesAStepPlannedFromTheWrongPrice() public {
        pool.setFee(DEVIATION);
        // The RPC lied: "the price is 3498", so the keeper "steps down" toward a
        // 3180 target — which on the real 3180 price is a 10% cut AWAY from it.
        uint256 lied = 3498e18;
        vm.prank(oracle);
        vm.expectRevert(abi.encodeWithSelector(SwapPool.PriceChanged.selector, address(weth), lied, WETH_PRICE));
        pool.setPrice(address(weth), lied, 3148_2e17); // "-10%" from the lie

        (,, uint256 price,) = _info(address(weth));
        assertEq(price, WETH_PRICE, "nothing moved");
        assertEq(pool.lastPriceUpdate(address(weth)), 0, "and the cooldown was not spent");
    }

    /// A step planned before someone else's update is stale, and refused.
    function test_M7_4_AStepPlannedBeforeAnotherUpdateIsRefused() public {
        pool.setFee(DEVIATION);
        vm.prank(oracle);
        pool.setPrice(address(weth), WETH_PRICE, 3300e18);
        vm.warp(block.timestamp + pool.minPriceUpdateInterval());
        vm.prank(oracle);
        vm.expectRevert(abi.encodeWithSelector(SwapPool.PriceChanged.selector, address(weth), WETH_PRICE, 3300e18));
        pool.setPrice(address(weth), WETH_PRICE, 3400e18);
    }
}
