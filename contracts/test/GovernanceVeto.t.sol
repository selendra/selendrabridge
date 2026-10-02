// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {Gate} from "../src/Gate.sol";
import {deployTestGate} from "./helpers/TestGate.sol";
import {TestToken} from "../src/TestToken.sol";
import {BridgeHash} from "../src/BridgeHash.sol";

/// @notice Audit 2026-10-02, M7-1 — the post-seal governance timelock gave no
///         usable veto against a stolen owner key.
///
///         PoC (from the audit): schedule `setBridgeDecimals(W)` on gate A, where
///         W is a CREATE2 address with no code yet, and
///         `setLocalToken(keccak(A, W), USDC)` on gate B; `setGuardian(0)` on
///         both in the same block, so nobody can cancel; wait 48 h; deploy W;
///         send W from A and drain B's USDC. The schedule events showed only a
///         hash, so observers could not even tell what was queued.
///
///         Fixed by: guardian removal/replacement is a timelocked action the
///         CURRENT guardian can cancel; typed schedule entry points that publish
///         the decoded parameters (the opaque `scheduleGovernance(bytes32)` is
///         gone); and a token must have code when it is scheduled.
contract GovernanceVetoTest is Test {
    Gate gateA; // the chain the worthless token W would be sent from
    Gate gateB; // the chain whose USDC vault the PoC drains
    TestToken usdc;

    address guardian = address(0x6A2D);
    address attacker = address(0xBAD);

    uint256 constant CHAIN_A = 1337;
    uint256 constant CHAIN_B = 1338;
    uint256 constant VAULT = 1_000_000e18;

    bytes32 constant W_SALT = keccak256("worthless");

    function setUp() public {
        address[] memory validators = new address[](1);
        validators[0] = vm.addr(0xA11CE);

        gateA = deployTestGate(validators, 1);
        gateA.setGuardian(guardian);
        gateA.setSupportedChain(CHAIN_B, true);
        gateA.seal();

        gateB = deployTestGate(validators, 1);
        gateB.setGuardian(guardian);
        gateB.setSupportedChain(CHAIN_A, true);
        usdc = new TestToken("USD Coin", "USDC");
        gateB.setBridgeDecimals(address(usdc), 18);
        gateB.seal();
        usdc.mint(address(gateB), VAULT);
    }

    /// The CREATE2 address W will be deployed at — known in advance, no code yet.
    function _w() internal view returns (address) {
        bytes memory init = abi.encodePacked(type(TestToken).creationCode, abi.encode("W", "W"));
        return vm.computeCreate2Address(W_SALT, keccak256(init), address(this));
    }

    // -----------------------------------------------------------------
    // The audit PoC, ported
    // -----------------------------------------------------------------

    function test_PoC_GuardianVetoSurvivesAndCodelessTokenIsRefused() public {
        address w = _w();
        assertEq(w.code.length, 0, "W does not exist yet");
        bytes32 wId = BridgeHash.getDebridgeId(CHAIN_A, w);

        // Step 1 of the PoC — queue W's wire scale on A before W exists. Refused:
        // there is nothing for anyone to review during the delay.
        vm.expectRevert(abi.encodeWithSelector(Gate.TokenHasNoCode.selector, w));
        gateA.scheduleSetBridgeDecimals(w, 18);

        // Step 2 — map keccak(A, W) onto B's USDC. USDC has code, so it can be
        // queued — but the event now says exactly what it is.
        bytes32 corridor = gateB.setLocalTokenActionId(wId, address(usdc));
        uint256 readyAt = block.timestamp + gateB.GOVERNANCE_DELAY();
        vm.expectEmit(true, false, false, true, address(gateB));
        emit Gate.GovernanceScheduled(corridor, readyAt);
        vm.expectEmit(true, true, true, true, address(gateB));
        emit Gate.SetLocalTokenScheduled(corridor, wId, address(usdc), readyAt);
        gateB.scheduleSetLocalToken(wId, address(usdc));

        // Step 3 — remove the veto in the same block. No longer instant.
        bytes32 removal = gateB.setGuardianActionId(address(0));
        vm.expectRevert(abi.encodeWithSelector(Gate.GovernanceNotScheduled.selector, removal));
        gateB.setGuardian(address(0));
        assertEq(gateB.guardian(), guardian, "the guardian is still in place");

        // The owner queues the removal instead — and the guardian it would
        // remove cancels it, along with the corridor.
        gateB.scheduleSetGuardian(address(0));
        vm.startPrank(guardian);
        gateB.cancelScheduledGovernance(corridor);
        gateB.cancelScheduledGovernance(removal);
        vm.stopPrank();

        // Step 4 — 48 h later, W is deployed; nothing the owner queued survives.
        vm.warp(readyAt);
        TestToken deployed = new TestToken{salt: W_SALT}("W", "W");
        assertEq(address(deployed), w, "CREATE2 address as predicted");

        vm.expectRevert(abi.encodeWithSelector(Gate.GovernanceNotScheduled.selector, corridor));
        gateB.setLocalToken(wId, address(usdc));
        vm.expectRevert(abi.encodeWithSelector(Gate.GovernanceNotScheduled.selector, removal));
        gateB.setGuardian(address(0));

        assertEq(gateB.tokenOf(wId), address(0), "the drain corridor never opened");
        assertEq(gateB.guardian(), guardian);
        assertEq(usdc.balanceOf(address(gateB)), VAULT, "vault intact");

        // Now that W has code, its scale CAN be queued — in public, by name.
        bytes32 scale = gateA.setBridgeDecimalsActionId(w, 18);
        uint256 scaleReady = block.timestamp + gateA.GOVERNANCE_DELAY();
        vm.expectEmit(true, true, false, true, address(gateA));
        emit Gate.SetBridgeDecimalsScheduled(scale, w, 18, scaleReady);
        gateA.scheduleSetBridgeDecimals(w, 18);
    }

    /// Even when the owner waits the guardian removal out alongside the drain,
    /// the guardian sees both during the same window and cancels the drain.
    function test_GuardianRemovalAndDrainMatureTogether_GuardianStillCancelsTheDrain() public {
        bytes32 wId = BridgeHash.getDebridgeId(CHAIN_A, address(0xF4CE));
        bytes32 corridor = gateB.scheduleSetLocalToken(wId, address(usdc));
        gateB.scheduleSetGuardian(address(0));

        vm.prank(guardian);
        gateB.cancelScheduledGovernance(corridor);

        vm.warp(block.timestamp + gateB.GOVERNANCE_DELAY());
        gateB.setGuardian(address(0)); // the guardian let its removal through
        assertEq(gateB.guardian(), address(0));
        vm.expectRevert(abi.encodeWithSelector(Gate.GovernanceNotScheduled.selector, corridor));
        gateB.setLocalToken(wId, address(usdc));
    }

    // -----------------------------------------------------------------
    // setGuardian rules
    // -----------------------------------------------------------------

    function test_SetGuardian_ReplacementAfterTheDelay() public {
        address next = address(0x6A3E);
        bytes32 action = gateB.setGuardianActionId(next);

        vm.expectRevert(abi.encodeWithSelector(Gate.GovernanceNotScheduled.selector, action));
        gateB.setGuardian(next);

        uint256 readyAt = block.timestamp + gateB.GOVERNANCE_DELAY();
        vm.expectEmit(true, true, false, true, address(gateB));
        emit Gate.SetGuardianScheduled(action, next, readyAt);
        gateB.scheduleSetGuardian(next);

        vm.warp(readyAt - 1);
        vm.expectRevert(abi.encodeWithSelector(Gate.GovernanceNotReady.selector, action, readyAt));
        gateB.setGuardian(next);

        vm.warp(readyAt);
        vm.expectEmit(true, false, false, false, address(gateB));
        emit Gate.GuardianSet(next);
        gateB.setGuardian(next);
        assertEq(gateB.guardian(), next);
        assertEq(gateB.governanceReadyAt(action), 0, "one approval, one change");

        // The old guardian lost its veto; the new one has it.
        bytes32 a = gateB.scheduleAddValidator(address(0xB0B));
        vm.prank(guardian);
        vm.expectRevert(Gate.NotAuthorizedToPause.selector);
        gateB.cancelScheduledGovernance(a);
        vm.prank(next);
        gateB.cancelScheduledGovernance(a);
    }

    function test_SetGuardian_AppointingWhenNoneIsSetStaysInstant() public {
        address[] memory validators = new address[](1);
        validators[0] = vm.addr(0xA11CE);
        Gate g = deployTestGate(validators, 1);
        g.seal();
        assertEq(g.guardian(), address(0));
        g.setGuardian(guardian); // adds a veto, removes none
        assertEq(g.guardian(), guardian);
    }

    function test_SetGuardian_InstantDuringTheSetupPhase() public {
        address[] memory validators = new address[](1);
        validators[0] = vm.addr(0xA11CE);
        Gate g = deployTestGate(validators, 1);
        g.setGuardian(guardian);
        g.setGuardian(address(0x6A3E)); // unsealed and inside SETUP_WINDOW
        g.setGuardian(address(0));
        assertEq(g.guardian(), address(0));
    }

    function test_SetGuardian_SetupPhaseAlsoEndsOnTheDeadline() public {
        address[] memory validators = new address[](1);
        validators[0] = vm.addr(0xA11CE);
        Gate g = deployTestGate(validators, 1);
        g.setGuardian(guardian);
        vm.warp(g.setupDeadline() + 1); // never sealed, but the window closed
        bytes32 removal = g.setGuardianActionId(address(0));
        vm.expectRevert(abi.encodeWithSelector(Gate.GovernanceNotScheduled.selector, removal));
        g.setGuardian(address(0));
    }

    function test_SetGuardian_SameValueIsANoOp() public {
        gateB.setGuardian(guardian);
        assertEq(gateB.guardian(), guardian);
    }

    // -----------------------------------------------------------------
    // Typed scheduling
    // -----------------------------------------------------------------

    function test_TypedSchedules_EmitDecodedParameters() public {
        uint256 readyAt = block.timestamp + gateB.GOVERNANCE_DELAY();

        address v = address(0xB0B);
        bytes32 addId = gateB.addValidatorActionId(v);
        vm.expectEmit(true, true, false, true, address(gateB));
        emit Gate.AddValidatorScheduled(addId, v, readyAt);
        gateB.scheduleAddValidator(v);

        bytes32 lowerId = gateB.lowerThresholdActionId(1);
        vm.expectEmit(true, false, false, true, address(gateB));
        emit Gate.LowerThresholdScheduled(lowerId, 1, readyAt);
        gateB.scheduleLowerThreshold(1);

        TestToken t = new TestToken("T", "T");
        bytes32 decId = gateB.setBridgeDecimalsActionId(address(t), 6);
        vm.expectEmit(true, true, false, true, address(gateB));
        emit Gate.SetBridgeDecimalsScheduled(decId, address(t), 6, readyAt);
        gateB.scheduleSetBridgeDecimals(address(t), 6);

        assertEq(gateB.governanceReadyAt(gateB.addValidatorActionId(v)), readyAt);
        assertEq(gateB.governanceReadyAt(gateB.lowerThresholdActionId(1)), readyAt);
        assertEq(gateB.governanceReadyAt(gateB.setBridgeDecimalsActionId(address(t), 6)), readyAt);
    }

    function test_TypedSchedules_AreOwnerOnly() public {
        vm.startPrank(attacker);
        vm.expectRevert(Gate.NotOwner.selector);
        gateB.scheduleAddValidator(attacker);
        vm.expectRevert(Gate.NotOwner.selector);
        gateB.scheduleLowerThreshold(1);
        vm.expectRevert(Gate.NotOwner.selector);
        gateB.scheduleSetLocalToken(bytes32(uint256(1)), address(usdc));
        vm.expectRevert(Gate.NotOwner.selector);
        gateB.scheduleSetBridgeDecimals(address(usdc), 6);
        vm.expectRevert(Gate.NotOwner.selector);
        gateB.scheduleSetGuardian(attacker);
        vm.stopPrank();
    }

    function test_ScheduleSetLocalToken_RefusesACodelessToken() public {
        address ghost = address(0xC0DE1E55);
        vm.expectRevert(abi.encodeWithSelector(Gate.TokenHasNoCode.selector, ghost));
        gateB.scheduleSetLocalToken(bytes32(uint256(1)), ghost);
        vm.expectRevert(Gate.ZeroAddress.selector);
        gateB.scheduleSetLocalToken(bytes32(uint256(1)), address(0));
    }

    function test_ScheduleSetBridgeDecimals_ChecksWhatExecutionWould() public {
        vm.expectRevert(abi.encodeWithSelector(Gate.BridgeDecimalsAlreadySet.selector, address(usdc)));
        gateB.scheduleSetBridgeDecimals(address(usdc), 6);

        TestToken t = new TestToken("T", "T"); // 18 decimals
        vm.expectRevert(abi.encodeWithSelector(Gate.InvalidBridgeDecimals.selector, address(t), 19, 18));
        gateB.scheduleSetBridgeDecimals(address(t), 19);
    }

    function test_ScheduleAddValidator_And_LowerThreshold_RefuseZero() public {
        vm.expectRevert(Gate.ZeroValidator.selector);
        gateB.scheduleAddValidator(address(0));
        vm.expectRevert(abi.encodeWithSelector(Gate.InvalidThreshold.selector, 0, 1));
        gateB.scheduleLowerThreshold(0);
    }

    /// Ids carry a version tag, so a schedule made through the removed opaque
    /// `scheduleGovernance(bytes32)` before the upgrade can never be consumed.
    function test_ActionIds_AreVersioned_SoPreUpgradeSchedulesAreDead() public view {
        address v = address(0xB0B);
        assertTrue(gateB.addValidatorActionId(v) != keccak256(abi.encode("addValidator", v)));
        assertTrue(gateB.lowerThresholdActionId(1) != keccak256(abi.encode("lowerThreshold", uint256(1))));
        assertTrue(
            gateB.setLocalTokenActionId(bytes32(0), address(usdc))
                != keccak256(abi.encode("setLocalToken", bytes32(0), address(usdc)))
        );
        assertTrue(
            gateB.setBridgeDecimalsActionId(address(usdc), 6)
                != keccak256(abi.encode("setBridgeDecimals", address(usdc), uint8(6)))
        );
        // and the kinds never collide with each other
        assertTrue(gateB.setGuardianActionId(v) != gateB.addValidatorActionId(v));
    }

    /// The raw entry point is gone from the ABI.
    function test_OpaqueScheduleGovernanceIsGone() public {
        (bool ok,) = address(gateB).call(abi.encodeWithSignature("scheduleGovernance(bytes32)", bytes32(uint256(1))));
        assertFalse(ok);
    }
}

/// @notice Audit 2026-10-02, M7-12 — dust transfers drain the keeper/relayer gas
///         wallets. A per-token minimum send (local units, owner-set, default 0)
///         and a hard cap on `autoParams`.
contract SendLimitsTest is Test {
    Gate gate;
    TestToken tok;
    address user = address(0xBEEF);
    uint256 constant CHAIN_TO = 1338;

    function setUp() public {
        address[] memory validators = new address[](1);
        validators[0] = vm.addr(0xA11CE);
        gate = deployTestGate(validators, 1);
        tok = new TestToken("T", "T");
        gate.setBridgeDecimals(address(tok), 6); // unit = 1e12
        gate.setSupportedChain(CHAIN_TO, true);
        tok.mint(user, 1_000e18);
        vm.prank(user);
        tok.approve(address(gate), type(uint256).max);
    }

    function _send(uint256 amount, bytes memory autoParams) internal returns (bytes32) {
        vm.prank(user);
        return gate.send(address(tok), amount, CHAIN_TO, abi.encodePacked(user), autoParams);
    }

    function test_MinSend_DefaultsToZero_KeepingOldBehaviour() public {
        assertEq(gate.minSendAmount(address(tok)), 0);
        _send(1e12, ""); // one bridge unit
    }

    function test_MinSend_RefusesDust() public {
        vm.expectEmit(true, false, false, true, address(gate));
        emit Gate.MinSendAmountSet(address(tok), 5e18);
        gate.setMinSendAmount(address(tok), 5e18);

        vm.expectRevert(abi.encodeWithSelector(Gate.BelowMinSendAmount.selector, 5e18 - 1e12, 5e18));
        _send(5e18 - 1e12, "");

        _send(5e18, ""); // exactly the minimum passes

        gate.setMinSendAmount(address(tok), 0); // and it can be lifted again
        _send(1e12, "");
    }

    function test_MinSend_IsPerToken() public {
        TestToken other = new TestToken("O", "O");
        gate.setBridgeDecimals(address(other), 18);
        gate.setMinSendAmount(address(tok), 5e18);
        other.mint(user, 1);
        vm.startPrank(user);
        other.approve(address(gate), 1);
        gate.send(address(other), 1, CHAIN_TO, abi.encodePacked(user), "");
        vm.stopPrank();
    }

    function test_MinSend_OwnerOnly_AndInstantAfterSeal() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(Gate.NotOwner.selector);
        gate.setMinSendAmount(address(tok), 1);

        vm.expectRevert(Gate.ZeroAddress.selector);
        gate.setMinSendAmount(address(0), 1);

        gate.seal();
        gate.setMinSendAmount(address(tok), 7e18); // no schedule needed
        assertEq(gate.minSendAmount(address(tok)), 7e18);
    }

    function test_AutoParams_CappedAtTheConstant() public {
        uint256 max = gate.MAX_AUTO_PARAMS_LENGTH();
        assertEq(max, 4096);
        // Never above what the off-chain store accepts (bridge-db
        // MAX_AUTO_PARAMS_BYTES = 32 KiB of raw bytes).
        assertLe(max, 32 * 1024);

        _send(1e12, new bytes(max));

        vm.expectRevert(abi.encodeWithSelector(Gate.AutoParamsTooLong.selector, max + 1, max));
        _send(1e12, new bytes(max + 1));
    }

    /// A real swap-and-bridge payload fits with a wide margin.
    function test_AutoParams_RealPayloadFits() public view {
        Gate.AutoParamsTo memory ap = Gate.AutoParamsTo({
            executionFee: 0,
            flags: 0,
            fallbackAddress: abi.encodePacked(user),
            data: abi.encode(address(tok), user, type(uint256).max)
        });
        assertLt(abi.encode(ap).length * 8, gate.MAX_AUTO_PARAMS_LENGTH());
    }
}
