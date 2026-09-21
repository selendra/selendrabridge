// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {Gate} from "../src/Gate.sol";
import {BridgeHash} from "../src/BridgeHash.sol";
import {SwapPool} from "../src/SwapPool.sol";
import {SwapRouter} from "../src/SwapRouter.sol";
import {deployTestGate} from "./helpers/TestGate.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract DecToken is ERC20 {
    uint8 private immutable _dec;

    constructor(string memory s, uint8 d) ERC20(s, s) {
        _dec = d;
    }

    function decimals() public view override returns (uint8) {
        return _dec;
    }

    function mint(address to, uint256 amt) external {
        _mint(to, amt);
    }
}

/// @notice Decimals normalisation: one asset, different decimals per chain.
///
///         Before it, a transfer carried the raw local amount, so 1 TST locked on
///         an 18-decimal chain (1e18 units) was claimable on a 6-decimal chain as
///         1e18 units — a trillion TST. Every transfer now travels in the asset's
///         bridge decimals and each gate converts with its own token's decimals.
contract DecimalsTest is Test {
    uint256 constant CHAIN_18 = 11155111; // TST at 18 decimals
    uint256 constant CHAIN_6 = 7777; // TST at 6 decimals (the SPL shape)
    uint256 constant CHAIN_9 = 9999; // TST at 9 decimals
    uint256 constant SOLANA = 7565164;
    uint8 constant BRIDGE_DEC = 6; // min over the mesh

    uint256 v1pk = 0xA11CE;
    address user = address(0xBEEF);
    address receiverAddr = address(0xCAFE);
    bytes receiver;

    Gate gate18;
    Gate gate6;
    Gate gate9;
    DecToken tst18;
    DecToken tst6;
    DecToken tst9;

    function setUp() public {
        address[] memory vals = new address[](1);
        vals[0] = vm.addr(v1pk);
        receiver = abi.encodePacked(receiverAddr);

        vm.chainId(CHAIN_18);
        gate18 = deployTestGate(vals, 1);
        tst18 = new DecToken("TST", 18);
        gate18.setBridgeDecimals(address(tst18), BRIDGE_DEC);
        gate18.setSupportedChain(CHAIN_6, true);
        gate18.setSupportedChain(CHAIN_9, true);
        gate18.setSupportedChain(SOLANA, true);

        vm.chainId(CHAIN_6);
        gate6 = deployTestGate(vals, 1);
        tst6 = new DecToken("TST", 6);
        gate6.setBridgeDecimals(address(tst6), BRIDGE_DEC);
        gate6.setSupportedChain(CHAIN_18, true);
        gate6.setLocalToken(BridgeHash.getDebridgeId(CHAIN_18, address(tst18)), address(tst6));
        tst6.mint(address(gate6), 1_000_000e6);

        vm.chainId(CHAIN_9);
        gate9 = deployTestGate(vals, 1);
        tst9 = new DecToken("TST", 9);
        gate9.setBridgeDecimals(address(tst9), BRIDGE_DEC);
        gate9.setLocalToken(BridgeHash.getDebridgeId(CHAIN_18, address(tst18)), address(tst9));
        tst9.mint(address(gate9), 1_000_000e9);

        // and the return leg: 6-decimal chain -> 18-decimal chain
        vm.chainId(CHAIN_18);
        gate18.setLocalToken(BridgeHash.getDebridgeId(CHAIN_6, address(tst6)), address(tst18));
        tst18.mint(address(gate18), 1_000_000e18);
        tst18.mint(user, 1_000e18);
        vm.prank(user);
        tst18.approve(address(gate18), type(uint256).max);

        // Wiring complete. `claim` refuses an unsealed gate (M-1), and the
        // registration tests below that need the setup phase deploy their own.
        gate18.seal();
        gate6.seal();
        gate9.seal();
    }

    function _sign(bytes32 id) internal view returns (bytes[] memory sigs) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(v1pk, MessageHashUtils.toEthSignedMessageHash(id));
        sigs = new bytes[](1);
        sigs[0] = abi.encodePacked(r, s, v);
    }

    function _send18(uint256 localAmount, uint256 chainTo) internal returns (bytes32 id) {
        vm.chainId(CHAIN_18);
        vm.prank(user);
        id = gate18.send(address(tst18), localAmount, chainTo, receiver, "");
    }

    // ------------------------------------------------------------------
    // The bug, and the fix
    // ------------------------------------------------------------------

    /// 1.5 TST from 18 decimals arrives as 1.5 TST at 6 decimals — not 1.5e18 units.
    function test_EighteenToSix_PaysTheSameValue() public {
        bytes32 did = BridgeHash.getDebridgeId(CHAIN_18, address(tst18));
        vm.expectEmit(false, true, false, false);
        emit Gate.Sent(bytes32(0), did, 1_500_000, CHAIN_18, CHAIN_6, receiver, 0, "", "", address(tst18));
        bytes32 id = _send18(1.5e18, CHAIN_6);

        // the id commits to the WIRE amount
        assertEq(
            id,
            gate18.computeSubmissionId(did, 1_500_000, CHAIN_18, CHAIN_6, 0, receiver, "", abi.encodePacked(user))
        );
        assertEq(tst18.balanceOf(address(gate18)), 1_000_000e18 + 1.5e18, "locks the LOCAL amount");

        vm.chainId(CHAIN_6);
        gate6.claim(did, 1_500_000, CHAIN_18, 0, receiver, "", "", _sign(id));
        assertEq(tst6.balanceOf(receiverAddr), 1.5e6, "1.5 TST at 6 decimals");
    }

    function test_EighteenToNine_PaysTheSameValue() public {
        bytes32 did = BridgeHash.getDebridgeId(CHAIN_18, address(tst18));
        bytes32 id = _send18(2.25e18, CHAIN_9);
        vm.chainId(CHAIN_9);
        gate9.claim(did, 2_250_000, CHAIN_18, 0, receiver, "", "", _sign(id));
        assertEq(tst9.balanceOf(receiverAddr), 2.25e9);
    }

    /// Scaling UP is the direction a naive fix gets wrong: 6 -> 18 must multiply.
    function test_SixToEighteen_PaysTheSameValue() public {
        vm.chainId(CHAIN_6);
        tst6.mint(user, 10e6);
        vm.startPrank(user);
        tst6.approve(address(gate6), type(uint256).max);
        bytes32 id = gate6.send(address(tst6), 3.75e6, CHAIN_18, receiver, "");
        vm.stopPrank();

        vm.chainId(CHAIN_18);
        gate18.claim(BridgeHash.getDebridgeId(CHAIN_6, address(tst6)), 3_750_000, CHAIN_6, 0, receiver, "", "", _sign(id));
        assertEq(tst18.balanceOf(receiverAddr), 3.75e18);
    }

    // ------------------------------------------------------------------
    // Precision: exact or revert
    // ------------------------------------------------------------------

    function test_Send_RevertsOnPrecisionTheBridgeCannotCarry() public {
        vm.chainId(CHAIN_18);
        uint256 amount = 1e18 + 1; // one wei below the 1e12 bridge unit
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Gate.InexactAmount.selector, amount, 1e12));
        gate18.send(address(tst18), amount, CHAIN_6, receiver, "");
        assertEq(gate18.nonceTo(CHAIN_6), 0, "nothing sent");
    }

    function test_Send_RevertsBelowOneBridgeUnit() public {
        vm.chainId(CHAIN_18);
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Gate.InexactAmount.selector, 1e11, 1e12));
        gate18.send(address(tst18), 1e11, CHAIN_6, receiver, "");
    }

    function test_Views_ConvertBothWays() public view {
        assertEq(gate18.bridgeUnit(address(tst18)), 1e12);
        assertEq(gate18.toBridgeAmount(address(tst18), 7e18), 7e6);
        assertEq(gate18.toLocalAmount(address(tst18), 7e6), 7e18);
        assertEq(gate6.bridgeUnit(address(tst6)), 1, "a token AT bridge decimals converts 1:1");
    }

    // ------------------------------------------------------------------
    // Refund returns exactly what was locked
    // ------------------------------------------------------------------

    function test_Refund_ReturnsTheLocalAmountLocked() public {
        uint256 before = tst18.balanceOf(user);
        bytes32 id = _send18(4.2e18, CHAIN_6);
        bytes32 did = BridgeHash.getDebridgeId(CHAIN_18, address(tst18));
        assertEq(tst18.balanceOf(user), before - 4.2e18);

        vm.chainId(CHAIN_18);
        gate18.refund(
            address(tst18), did, 4_200_000, CHAIN_6, 0, receiver, "", "", _sign(BridgeHash.getRefundId(id))
        );
        assertEq(tst18.balanceOf(user), before, "refund is the full local amount");
    }

    // ------------------------------------------------------------------
    // The Solana width cap applies to the wire amount
    // ------------------------------------------------------------------

    /// 10^12 TST from an 18-decimal chain is 10^30 local units — far past u64 —
    /// but only 10^18 at 6 bridge decimals, which the Solana program can carry.
    function test_ToSolana_CapIsOnTheWireAmount() public {
        tst18.mint(user, 1e30);
        bytes memory sol = abi.encodePacked(bytes32(uint256(0xABCD)));
        vm.chainId(CHAIN_18);
        vm.prank(user);
        gate18.send(address(tst18), 1e30, SOLANA, sol, "");

        uint256 tooWide = (uint256(type(uint64).max) + 1) * 1e12;
        tst18.mint(user, tooWide);
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Gate.AmountTooWide.selector, uint256(type(uint64).max) + 1));
        gate18.send(address(tst18), tooWide, SOLANA, sol, "");
    }

    // ------------------------------------------------------------------
    // Registration rules
    // ------------------------------------------------------------------

    function test_Send_RefusesATokenWithNoBridgeDecimals() public {
        DecToken raw = new DecToken("RAW", 18);
        raw.mint(user, 1e18);
        vm.chainId(CHAIN_18);
        vm.startPrank(user);
        raw.approve(address(gate18), 1e18);
        vm.expectRevert(abi.encodeWithSelector(Gate.BridgeDecimalsUnset.selector, address(raw)));
        gate18.send(address(raw), 1e18, CHAIN_6, receiver, "");
        vm.stopPrank();
    }

    function test_SetLocalToken_RefusesATokenWithNoBridgeDecimals() public {
        // A gate still in its setup phase: the point is the decimals check, not
        // the governance delay a sealed gate would hit first.
        address[] memory vals = new address[](1);
        vals[0] = vm.addr(v1pk);
        Gate fresh = deployTestGate(vals, 1);
        DecToken raw = new DecToken("RAW", 18);
        vm.expectRevert(abi.encodeWithSelector(Gate.BridgeDecimalsUnset.selector, address(raw)));
        fresh.setLocalToken(keccak256("corridor"), address(raw));
    }

    function test_SetBridgeDecimals_IsWriteOnce() public {
        vm.expectRevert(abi.encodeWithSelector(Gate.BridgeDecimalsAlreadySet.selector, address(tst18)));
        gate18.setBridgeDecimals(address(tst18), 18);
    }

    function test_SetBridgeDecimals_CannotExceedTheTokensOwn() public {
        DecToken t = new DecToken("T", 6);
        vm.expectRevert(abi.encodeWithSelector(Gate.InvalidBridgeDecimals.selector, address(t), 8, 6));
        gate18.setBridgeDecimals(address(t), 8);
    }

    function test_SetBridgeDecimals_OnlyOwner() public {
        DecToken t = new DecToken("T", 18);
        vm.prank(user);
        vm.expectRevert(Gate.NotOwner.selector);
        gate18.setBridgeDecimals(address(t), 6);
    }

    /// After seal a lower value on a destination multiplies every claim of the
    /// token, so it waits out the governance delay like a corridor does — and
    /// the schedule is bound to the exact value.
    function test_SetBridgeDecimals_AfterSeal_NeedsAMaturedScheduleForThatValue() public {
        DecToken t = new DecToken("T", 18);
        // (setUp already sealed it.)
        bytes32 action = gate18.setBridgeDecimalsActionId(address(t), 6);
        vm.expectRevert(abi.encodeWithSelector(Gate.GovernanceNotScheduled.selector, action));
        gate18.setBridgeDecimals(address(t), 6);

        gate18.scheduleGovernance(action);
        vm.warp(block.timestamp + gate18.GOVERNANCE_DELAY());
        bytes32 other = gate18.setBridgeDecimalsActionId(address(t), 2);
        vm.expectRevert(abi.encodeWithSelector(Gate.GovernanceNotScheduled.selector, other));
        gate18.setBridgeDecimals(address(t), 2);

        gate18.setBridgeDecimals(address(t), 6);
        assertEq(gate18.bridgeUnit(address(t)), 1e12);
    }

    // ------------------------------------------------------------------
    // H-2 (audit 2026-09-16): the scale is not in the submissionId
    // ------------------------------------------------------------------

    /// `bridgeDecimalsFor` answers "what scale would THIS gate pay `debridgeId`
    /// out at", in one call, from the id off-chain actually holds. Validators
    /// compare the two ends with it and refuse to sign a mismatch — the only
    /// place it can still be stopped, because `claim` is permissionless.
    function test_BridgeDecimalsFor_ResolvesThroughTheCorridor() public view {
        bytes32 did = BridgeHash.getDebridgeId(CHAIN_18, address(tst18));
        (bool set, uint8 bd, uint8 ld, address local) = gate6.bridgeDecimalsFor(did);
        assertTrue(set);
        assertEq(bd, BRIDGE_DEC);
        assertEq(ld, 6, "the payout token's own decimals");
        assertEq(local, address(tst6));

        // Same asset, the 9-decimal chain: same wire scale, different local one.
        (, uint8 bd9, uint8 ld9, address local9) = gate9.bridgeDecimalsFor(did);
        assertEq(bd9, BRIDGE_DEC, "the mesh agrees on the wire scale");
        assertEq(ld9, 9);
        assertEq(local9, address(tst9));
    }

    /// It must not revert on an unregistered corridor: a caller has to tell "no
    /// corridor here" apart from "corridor at scale 0", and a reverting probe
    /// would make a validator's check fail for the wrong reason.
    function test_BridgeDecimalsFor_UnknownCorridorIsNotARevert() public view {
        (bool set, uint8 bd, uint8 ld, address local) =
            gate6.bridgeDecimalsFor(keccak256("no such corridor"));
        assertFalse(set);
        assertEq(bd, 0);
        assertEq(ld, 0);
        assertEq(local, address(0));
    }

    /// THE FINDING ITSELF. A destination registered one digit off pays a power of
    /// ten too much on an ORDINARY user's transfer — no attacker input anywhere,
    /// and the submissionId is byte-identical either way, which is exactly why
    /// nothing on-chain catches it.
    function test_AMisregisteredDestinationOverpaysByAPowerOfTen() public {
        uint256 badChain = CHAIN_9 + 1;
        address[] memory vals = new address[](1);
        vals[0] = vm.addr(v1pk);

        vm.chainId(badChain);
        Gate bad = deployTestGate(vals, 1);
        DecToken tstBad = new DecToken("TST", 9);
        bad.setBridgeDecimals(address(tstBad), 3); // <-- the typo; the mesh uses 6
        bytes32 did = BridgeHash.getDebridgeId(CHAIN_18, address(tst18));
        bad.setLocalToken(did, address(tstBad));
        bad.seal();
        tstBad.mint(address(bad), 1_000_000e9);

        vm.chainId(CHAIN_18);
        gate18.setSupportedChain(badChain, true);
        bytes32 id = _send18(1e18, badChain); // the user sends exactly 1 TST

        vm.chainId(badChain);
        bad.claim(did, 1_000_000, CHAIN_18, 0, receiver, "", "", _sign(id));

        // 1 TST locked, 1,000 TST released. Each gate behaved exactly as
        // configured — only the two ends DISAGREEING is wrong, and neither can
        // see the other.
        assertEq(tstBad.balanceOf(receiverAddr), 1_000e9, "overpaid by 10^3");

        // The discrepancy is visible in one call from each side, which is what
        // the off-chain refusal is built on.
        (, uint8 srcBd,,) = gate6.bridgeDecimalsFor(did); // a correctly wired peer
        (, uint8 dstBd,,) = bad.bridgeDecimalsFor(did);
        assertEq(srcBd, BRIDGE_DEC);
        assertEq(dstBd, 3);
        assertTrue(srcBd != dstBd, "a validator comparing these refuses to sign");
    }

}

/// @notice The cross-chain swap carries a pool output, which almost never lands
///         on a bridge unit. The router bridges the convertible part, returns the
///         dust, and converts back on arrival.
contract DecimalsRouterTest is Test {
    uint256 constant CHAIN_A = 1337;
    uint256 constant CHAIN_B = 8453;

    uint256 v1pk = 0xA11CE;
    address user = address(0xBEEF);
    address finalReceiver = address(0xF1A1);

    Gate gateA;
    Gate gateB;
    DecToken usdA; // 18 decimals on A
    DecToken usdB; // 6 decimals on B
    DecToken weth;
    DecToken tt;
    SwapPool poolA;
    SwapPool poolB;
    SwapRouter routerA;
    SwapRouter routerB;

    function setUp() public {
        address[] memory vals = new address[](1);
        vals[0] = vm.addr(v1pk);

        vm.chainId(CHAIN_A);
        gateA = deployTestGate(vals, 1);
        gateA.setSupportedChain(CHAIN_B, true);
        usdA = new DecToken("USDa", 18);
        weth = new DecToken("WETH", 18);
        gateA.setBridgeDecimals(address(usdA), 6);
        poolA = new SwapPool(address(usdA), 1000);
        // a price with more precision than 6 decimals, so the output has dust
        poolA.listToken(address(weth), 3180.1234567891e18);
        _seed(poolA, usdA, 10_000_000e18);
        _seed(poolA, weth, 100e18);
        routerA = new SwapRouter(gateA, poolA);

        vm.chainId(CHAIN_B);
        gateB = deployTestGate(vals, 1);
        usdB = new DecToken("USDb", 6);
        tt = new DecToken("TT", 18);
        gateB.setBridgeDecimals(address(usdB), 6);
        poolB = new SwapPool(address(usdB), 1000);
        poolB.listToken(address(tt), 2e18);
        _seed(poolB, usdB, 10_000_000e6);
        _seed(poolB, tt, 1_000_000e18);
        routerB = new SwapRouter(gateB, poolB);
        gateB.setLocalToken(BridgeHash.getDebridgeId(CHAIN_A, address(usdA)), address(usdB));
        gateA.seal();
        gateB.seal();
        usdB.mint(address(gateB), 10_000_000e6);

        routerA.setRemoteRouter(CHAIN_B, abi.encodePacked(address(routerB)));
        routerB.setRemoteRouter(CHAIN_A, abi.encodePacked(address(routerA)));
    }

    function _seed(SwapPool pool, DecToken token, uint256 amt) internal {
        token.mint(address(this), amt);
        token.approve(address(pool), amt);
        pool.seedLiquidity(address(token), amt);
    }

    function test_SwapAndBridge_BridgesWholeUnitsReturnsDustAndPaysOutOnArrival() public {
        vm.chainId(CHAIN_A);
        uint256 stableOut = poolA.quote(address(weth), address(usdA), 1e18);
        uint256 dust = stableOut % 1e12;
        assertGt(dust, 0, "test needs a pool output with dust");
        uint256 wire = stableOut / 1e12;

        weth.mint(user, 1e18);
        vm.startPrank(user);
        weth.approve(address(routerA), 1e18);
        bytes32 id = routerA.swapAndBridge(address(weth), 1e18, 0, CHAIN_B, address(tt), finalReceiver, 0);
        vm.stopPrank();

        assertEq(usdA.balanceOf(user), dust, "dust handed back to the caller");
        assertEq(usdA.balanceOf(address(routerA)), 0, "router keeps nothing");

        bytes memory autoParams = abi.encode(
            Gate.AutoParamsTo({
                executionFee: 0,
                flags: 0,
                fallbackAddress: abi.encodePacked(finalReceiver),
                data: abi.encode(address(tt), finalReceiver, uint256(0))
            })
        );
        bytes32 did = BridgeHash.getDebridgeId(CHAIN_A, address(usdA));
        bytes memory recv = abi.encodePacked(address(routerB));
        bytes memory sender = abi.encodePacked(address(routerA));
        assertEq(id, gateA.computeSubmissionId(did, wire, CHAIN_A, CHAIN_B, 0, recv, autoParams, sender));

        vm.chainId(CHAIN_B);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(v1pk, MessageHashUtils.toEthSignedMessageHash(id));
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = abi.encodePacked(r, s, v);
        routerB.claimAndFinalize(did, wire, CHAIN_A, 0, recv, autoParams, sender, sigs);

        // `wire` USDb (6 decimals) swapped at TT = 2.0 → wire * 1e12 / 2 TT units
        assertEq(tt.balanceOf(finalReceiver), poolB.quote(address(usdB), address(tt), wire));
        assertEq(usdB.balanceOf(address(routerB)), 0, "no stable stranded at the router");
    }
}

/// @notice The router with a bridge unit > 1 on BOTH ends. `DecimalsRouterTest`
///         scales the source only — its destination stable is 6/6, so there
///         `toLocalAmount` is the identity and deleting the router's conversion
///         would pass every test. Here the destination stable has 18 decimals
///         bridged at 6: a claim releases `wire * 1e12`, and the swap, the owed
///         debt and the stable fallback must all be in that local amount.
contract DecimalsRouterScaledTest is Test {
    uint256 constant CHAIN_A = 1337;
    uint256 constant CHAIN_B = 8453;
    uint256 constant UNIT = 1e12; // 18 local decimals bridged at 6

    uint256 v1pk = 0xA11CE;
    address user = address(0xBEEF);
    address finalReceiver = address(0xF1A1);

    Gate gateA;
    Gate gateB;
    DecToken usdA; // 18 decimals, bridged at 6
    DecToken usdB; // 18 decimals, bridged at 6
    DecToken weth;
    DecToken tt;
    SwapPool poolA;
    SwapPool poolB;
    SwapRouter routerA;
    SwapRouter routerB;

    function setUp() public {
        address[] memory vals = new address[](1);
        vals[0] = vm.addr(v1pk);

        vm.chainId(CHAIN_A);
        gateA = deployTestGate(vals, 1);
        gateA.setSupportedChain(CHAIN_B, true);
        usdA = new DecToken("USDa", 18);
        weth = new DecToken("WETH", 18);
        gateA.setBridgeDecimals(address(usdA), 6);
        poolA = new SwapPool(address(usdA), 1000);
        poolA.listToken(address(weth), 3180e18);
        _seed(poolA, usdA, 10_000_000e18);
        _seed(poolA, weth, 100e18);
        routerA = new SwapRouter(gateA, poolA);

        vm.chainId(CHAIN_B);
        gateB = deployTestGate(vals, 1);
        usdB = new DecToken("USDb", 18);
        tt = new DecToken("TT", 18);
        gateB.setBridgeDecimals(address(usdB), 6);
        poolB = new SwapPool(address(usdB), 1000);
        poolB.listToken(address(tt), 2e18);
        _seed(poolB, usdB, 10_000_000e18);
        _seed(poolB, tt, 1_000_000e18);
        routerB = new SwapRouter(gateB, poolB);
        gateB.setLocalToken(BridgeHash.getDebridgeId(CHAIN_A, address(usdA)), address(usdB));
        gateA.seal();
        gateB.seal();
        usdB.mint(address(gateB), 10_000_000e18);

        routerA.setRemoteRouter(CHAIN_B, abi.encodePacked(address(routerB)));
        routerB.setRemoteRouter(CHAIN_A, abi.encodePacked(address(routerA)));
    }

    function _seed(SwapPool pool, DecToken token, uint256 amt) internal {
        token.mint(address(this), amt);
        token.approve(address(pool), amt);
        pool.seedLiquidity(address(token), amt);
    }

    struct Leg {
        bytes32 did;
        uint256 wire;
        bytes recv;
        bytes autoParams;
        bytes sender;
        bytes32 id;
    }

    /// 1 WETH -> 3180 USDa (no dust at this price) -> 3180e6 on the wire -> B.
    function _send() internal returns (Leg memory l) {
        vm.chainId(CHAIN_A);
        weth.mint(user, 1e18);
        vm.startPrank(user);
        weth.approve(address(routerA), 1e18);
        l.id = routerA.swapAndBridge(address(weth), 1e18, 0, CHAIN_B, address(tt), finalReceiver, 0);
        vm.stopPrank();
        l.wire = 3180e6;
        l.did = BridgeHash.getDebridgeId(CHAIN_A, address(usdA));
        l.recv = abi.encodePacked(address(routerB));
        l.sender = abi.encodePacked(address(routerA));
        l.autoParams = abi.encode(
            Gate.AutoParamsTo({
                executionFee: 0,
                flags: 0,
                fallbackAddress: abi.encodePacked(finalReceiver),
                data: abi.encode(address(tt), finalReceiver, uint256(0))
            })
        );
        assertEq(l.id, gateA.computeSubmissionId(l.did, l.wire, CHAIN_A, CHAIN_B, 0, l.recv, l.autoParams, l.sender));
        vm.chainId(CHAIN_B);
    }

    function _sigs(bytes32 id) internal view returns (bytes[] memory sigs) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(v1pk, MessageHashUtils.toEthSignedMessageHash(id));
        sigs = new bytes[](1);
        sigs[0] = abi.encodePacked(r, s, v);
    }

    function _finalize(address who, Leg memory l) internal {
        vm.prank(who);
        routerB.finalize(l.did, l.wire, CHAIN_A, 0, l.recv, l.autoParams, l.sender);
    }

    function test_Destination_SwapsTheLocalAmountTheClaimReleased() public {
        Leg memory l = _send();
        routerB.claimAndFinalize(l.did, l.wire, CHAIN_A, 0, l.recv, l.autoParams, l.sender, _sigs(l.id));

        // 3180e18 USDb at TT = 2.0 -> 1590 TT. Swapping the wire amount instead
        // (3180e6 units) would pay 1590e6 TT units — a trillionth.
        assertEq(tt.balanceOf(finalReceiver), 1590e18, "must swap the local amount");
        assertEq(usdB.balanceOf(address(routerB)), 0, "no stable stranded at the router");
    }

    function test_Destination_DeferredDebtAndFallbackAreInLocalUnits() public {
        Leg memory l = _send();
        gateB.claim(l.did, l.wire, CHAIN_A, 0, l.recv, l.autoParams, l.sender, _sigs(l.id));
        poolB.pause();

        _finalize(address(0xBAD), l);
        assertFalse(routerB.finalized(l.id));
        assertEq(routerB.owedStable(), l.wire * UNIT, "the debt is what the router holds, in local units");
        assertEq(usdB.balanceOf(address(routerB)), l.wire * UNIT);

        vm.warp(block.timestamp + routerB.FALLBACK_GRACE());
        _finalize(finalReceiver, l);
        assertTrue(routerB.finalized(l.id));
        assertEq(usdB.balanceOf(finalReceiver), l.wire * UNIT, "the fallback pays the local amount");
        assertEq(routerB.owedStable(), 0, "debt cleared exactly");
        assertEq(usdB.balanceOf(address(routerB)), 0);
    }

    /// A swap whose whole output is below one bridge unit has nothing to bridge:
    /// refused, and the caller keeps their input.
    function test_SwapAndBridge_AnOutputOfOnlyDustReverts() public {
        vm.chainId(CHAIN_A);
        uint256 amountIn = 1e8; // 1e-10 WETH -> 3.18e-7 USDa = 318_000_000_000 units < 1e12
        assertLt(poolA.quote(address(weth), address(usdA), amountIn), UNIT, "setup: must be sub-unit");
        weth.mint(user, amountIn);
        vm.startPrank(user);
        weth.approve(address(routerA), amountIn);
        vm.expectRevert(SwapRouter.ZeroAmount.selector);
        routerA.swapAndBridge(address(weth), amountIn, 0, CHAIN_B, address(tt), finalReceiver, 0);
        vm.stopPrank();
        assertEq(weth.balanceOf(user), amountIn, "input untouched");
        assertEq(gateA.nonceTo(CHAIN_B), 0, "nothing sent");
    }

    /// Paying in the stable skips the pool, and still returns the sub-unit tail.
    function test_SwapAndBridge_StableInputReturnsItsDust() public {
        vm.chainId(CHAIN_A);
        uint256 amountIn = 5e18 + 123; // 5 USDa and 123 units of dust
        usdA.mint(user, amountIn);
        vm.startPrank(user);
        usdA.approve(address(routerA), amountIn);
        routerA.swapAndBridge(address(usdA), amountIn, 0, CHAIN_B, address(tt), finalReceiver, 0);
        vm.stopPrank();
        assertEq(usdA.balanceOf(user), 123, "dust handed back");
        assertEq(usdA.balanceOf(address(routerA)), 0, "router keeps nothing");
        assertEq(usdA.balanceOf(address(gateA)), 5e18, "only whole units locked");
    }
}
