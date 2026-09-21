// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {Gate} from "../src/Gate.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @notice Upgrades the REAL live gate on a FORK of Sepolia, because the M-1/M-2
///         claims are about storage that only exists on chain: an append-only
///         layout is a property of the deployed slots, not of a fixture.
///
///         Opt-in — it needs a network, so it is skipped unless `LIVE_FORK_RPC`
///         is set. Skipped rather than failed: a missing RPC is not a defect, and
///         the unit suite already covers the logic. Run it with:
///
/// ```text
/// LIVE_FORK_RPC=https://ethereum-sepolia-rpc.publicnode.com \
///   forge test --match-contract LiveGateUpgradeTest -vv
/// ```
///
///         FORK ONLY. Every write here happens in the fork's memory: the
///         impersonated owner never signs anything, and nothing is broadcast.
contract LiveGateUpgradeTest is Test {
    /// mesh9's Sepolia gate (the PROXY — that address is the gate).
    address constant LIVE_GATE = 0xC7b0057651dF1Ec95Ad252b3F9aBE1adbDeb71a4;
    /// mesh9's TST on Sepolia.
    address constant LIVE_TST = 0x6892359A0070Cfe9a8aB8128dD1E9321f87aB9f5;
    /// mesh9's TST on Hoodi — the SOURCE token of the corridor Sepolia pays out.
    address constant HOODI_TST = 0x76134531691F3dFe20128fF8B6283462Ba3947E4;
    uint256 constant HOODI = 560048;

    Gate gate = Gate(LIVE_GATE);
    address owner;

    function setUp() public {
        string memory rpc = vm.envOr("LIVE_FORK_RPC", string(""));
        if (bytes(rpc).length == 0) {
            vm.skip(true, "set LIVE_FORK_RPC to run the live-gate fork check");
            return;
        }
        vm.createSelectFork(rpc);
        owner = gate.owner();
    }

    /// Everything the gate knows must survive the implementation swap, and the
    /// newly appended slots must come up as virgin storage rather than as
    /// whatever `__gap` used to hold.
    function test_LiveGate_UpgradesInPlaceWithoutLosingState() public {
        // --- before ---
        bytes32 domainBefore = gate.bridgeDomain();
        uint256 thresholdBefore = gate.threshold();
        uint256 validatorsBefore = gate.validatorCount();
        bool sealedBefore = gate.isSealed();
        address guardianBefore = gate.guardian();
        uint256 nonceBefore = gate.nonceTo(HOODI);
        (bool tstSet, uint8 tstBridge, uint8 tstLocal) = gate.bridgeDecimalsOf(LIVE_TST);
        uint256 liquidityBefore = IERC20(LIVE_TST).balanceOf(LIVE_GATE);

        emit log_named_bytes32("bridgeDomain", domainBefore);
        emit log_named_uint("threshold", thresholdBefore);
        emit log_named_uint("validatorCount", validatorsBefore);
        emit log_named_uint("TST bridgeDecimals", tstBridge);
        emit log_named_uint("TST liquidity", liquidityBefore);
        assertTrue(sealedBefore, "precondition: the live gate is sealed");
        assertTrue(tstSet, "precondition: TST is registered");

        // --- upgrade, through the gate's own 48 h timelock ---
        address impl = address(new Gate());
        vm.startPrank(owner);
        gate.scheduleUpgrade(impl);
        vm.warp(block.timestamp + gate.UPGRADE_DELAY());
        UUPSUpgradeable(LIVE_GATE).upgradeToAndCall(impl, "");
        vm.stopPrank();

        // --- after ---
        assertEq(gate.bridgeDomain(), domainBefore, "bridgeDomain moved");
        assertEq(gate.threshold(), thresholdBefore, "threshold moved");
        assertEq(gate.validatorCount(), validatorsBefore, "validatorCount moved");
        assertEq(gate.guardian(), guardianBefore, "guardian moved");
        assertEq(gate.owner(), owner, "owner moved");
        assertEq(gate.nonceTo(HOODI), nonceBefore, "nonce moved: would strand in-flight ids");
        assertEq(IERC20(LIVE_TST).balanceOf(LIVE_GATE), liquidityBefore, "liquidity moved");
        assertTrue(gate.isSealed(), "seal must survive: `claim` now depends on it");

        (bool setAfter, uint8 bridgeAfter, uint8 localAfter) = gate.bridgeDecimalsOf(LIVE_TST);
        assertTrue(setAfter, "TST registration lost");
        assertEq(bridgeAfter, tstBridge, "TST bridge decimals changed");
        assertEq(localAfter, tstLocal, "TST local decimals changed");

        // The appended slot reads as untouched gap, so the gate does NOT get a
        // fresh instant-registration window out of the upgrade (M-1 + M-2).
        assertEq(gate.setupDeadline(), 0, "setupDeadline must read as virgin gap");
        assertFalse(gate.inSetupPhase(), "an upgraded live gate is never in setup");
    }

    /// The new function set has to work on the real storage, not just on a
    /// freshly deployed fixture.
    function test_LiveGate_NewFunctionsWorkOnRealState() public {
        address impl = address(new Gate());
        vm.startPrank(owner);
        gate.scheduleUpgrade(impl);
        vm.warp(block.timestamp + gate.UPGRADE_DELAY());
        UUPSUpgradeable(LIVE_GATE).upgradeToAndCall(impl, "");
        vm.stopPrank();

        // A corridor the live gate really serves: TST arriving FROM Hoodi is
        // keyed by the SOURCE token, and pays out Sepolia's own TST.
        bytes32 did = keccak256(abi.encodePacked(HOODI, HOODI_TST));
        (bool set, uint8 bridgeDec, uint8 localDec, address localToken) = gate.bridgeDecimalsFor(did);
        emit log_named_address("tokenOf(Hoodi->Sepolia TST)", localToken);
        emit log_named_uint("corridor bridgeDecimals", bridgeDec);
        assertTrue(set, "the live corridor must resolve through the new function");
        assertEq(localToken, LIVE_TST, "and pay out Sepolia TST");
        assertEq(bridgeDec, 6, "mesh9 bridges TST at 6");
        assertEq(localDec, 18, "Sepolia TST is an 18-decimal ERC-20");

        // Registration still takes the public delay after the upgrade.
        bytes32 fresh = keccak256("no.such.corridor");
        bytes32 action = gate.setLocalTokenActionId(fresh, LIVE_TST);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(Gate.GovernanceNotScheduled.selector, action));
        gate.setLocalToken(fresh, LIVE_TST);
    }

    /// The migration is a no-op on a gate that is already at the new semantics:
    /// every token it lists is registered, so nothing is re-scaled.
    function test_LiveGate_InitializeV2_CannotRescaleARegisteredAsset() public {
        address impl = address(new Gate());
        address[] memory tokens = new address[](1);
        tokens[0] = LIVE_TST;
        uint256[] memory chains = new uint256[](1);
        chains[0] = HOODI;

        (, uint8 bridgeBefore,) = gate.bridgeDecimalsOf(LIVE_TST);

        vm.startPrank(owner);
        gate.scheduleUpgrade(impl);
        vm.warp(block.timestamp + gate.UPGRADE_DELAY());
        UUPSUpgradeable(LIVE_GATE).upgradeToAndCall(
            impl, abi.encodeCall(Gate.initializeV2, (tokens, chains))
        );
        vm.stopPrank();

        (, uint8 bridgeAfter,) = gate.bridgeDecimalsOf(LIVE_TST);
        assertEq(bridgeAfter, bridgeBefore, "a registered asset must keep its scale");
        assertTrue(bridgeAfter != 18 || bridgeBefore == 18, "identity must not be forced onto it");
    }

    function _registered(address token) internal view returns (bool ok) {
        (ok,,) = gate.bridgeDecimalsOf(token);
    }
}
