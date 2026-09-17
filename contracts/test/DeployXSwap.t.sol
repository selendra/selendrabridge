// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {Gate} from "../src/Gate.sol";
import {BridgeHash} from "../src/BridgeHash.sol";
import {DeployXSwap} from "../script/DeployXSwap.s.sol";
import {SwapRouter} from "../src/SwapRouter.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @notice The demo cross-chain-swap script must produce a stack that actually
///         swaps across chains. It used to deploy a gate with no bridge decimals,
///         no peer and no corridor, so the first `swapAndBridge` reverted and the
///         working setup existed only as `cast` calls in `xswap.sh`.
contract DeployXSwapTest is Test {
    uint256 constant CHAIN_A = 1337;
    uint256 constant CHAIN_B = 1338;
    uint256 constant WETH_PRICE = 3180e18;
    uint256 constant TT_PRICE = 2e18;

    uint256 validatorPk = 0xA11CE;
    address user = address(0xBEEF);
    address finalReceiver = address(0xF1A1);

    DeployXSwap depA;
    DeployXSwap depB;
    DeployXSwap.Stack a;
    DeployXSwap.Stack b;

    function setUp() public {
        address validator = vm.addr(validatorPk);

        vm.chainId(CHAIN_A);
        depA = new DeployXSwap();
        a = depA._deploy(DeployXSwap.Params(validator, WETH_PRICE, "WETH", address(depA)));

        vm.chainId(CHAIN_B);
        depB = new DeployXSwap();
        b = depB._deploy(DeployXSwap.Params(validator, TT_PRICE, "TT", address(depB)));
    }

    function _wireBoth() internal {
        vm.chainId(CHAIN_A);
        depA._wire(a.gate, a.router, address(a.usd), CHAIN_B, address(b.usd), address(b.router));
        vm.chainId(CHAIN_B);
        depB._wire(b.gate, b.router, address(b.usd), CHAIN_A, address(a.usd), address(a.router));
    }

    function test_Deploy_RegistersTheStablesBridgeDecimals() public view {
        assertEq(a.gate.bridgeUnit(address(a.usd)), 1);
        assertEq(b.gate.bridgeUnit(address(b.usd)), 1);
        assertFalse(a.gate.isSealed(), "sealed only once the corridor is wired");
    }

    function test_Wire_SealsAfterMappingTheCorridor() public {
        _wireBoth();
        assertTrue(a.gate.isSealed() && b.gate.isSealed(), "both gates sealed");
        assertTrue(a.gate.supportedChain(CHAIN_B) && b.gate.supportedChain(CHAIN_A));
        assertEq(b.gate.tokenOf(BridgeHash.getDebridgeId(CHAIN_A, address(a.usd))), address(b.usd));
        assertEq(a.gate.tokenOf(BridgeHash.getDebridgeId(CHAIN_B, address(b.usd))), address(a.usd));
    }

    /// End to end on what the script produced: WETH on A -> stable -> TT on B.
    function test_TheDeployedStackSwapsAcrossChains() public {
        _wireBoth();
        vm.chainId(CHAIN_B);
        b.usd.mint(address(b.gate), 10_000_000e6); // destination liquidity, after seal

        vm.chainId(CHAIN_A);
        a.alt.mint(user, 1e18);
        vm.startPrank(user);
        a.alt.approve(address(a.router), 1e18);
        bytes32 id = a.router.swapAndBridge(address(a.alt), 1e18, 0, CHAIN_B, address(b.alt), finalReceiver, 0);
        vm.stopPrank();

        bytes32 did = BridgeHash.getDebridgeId(CHAIN_A, address(a.usd));
        bytes memory autoParams = abi.encode(
            Gate.AutoParamsTo({
                executionFee: 0,
                flags: 0,
                fallbackAddress: abi.encodePacked(finalReceiver),
                data: abi.encode(address(b.alt), finalReceiver, uint256(0))
            })
        );
        bytes memory recv = abi.encodePacked(address(b.router));
        bytes memory sender = abi.encodePacked(address(a.router));

        vm.chainId(CHAIN_B);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(validatorPk, MessageHashUtils.toEthSignedMessageHash(id));
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = abi.encodePacked(r, s, v);
        b.router.claimAndFinalize(did, 3180e6, CHAIN_A, 0, recv, autoParams, sender, sigs);

        assertEq(b.alt.balanceOf(finalReceiver), 1590e18, "3180 USD of WETH buys 1590 TT at 2.0");
    }

    /// Without `wire`, the deployed stack refuses to send rather than locking
    /// funds toward an unlisted chain.
    function test_BeforeWire_SendIsRefused() public {
        vm.chainId(CHAIN_A);
        a.alt.mint(user, 1e18);
        vm.startPrank(user);
        a.alt.approve(address(a.router), 1e18);
        vm.expectRevert(abi.encodeWithSelector(SwapRouter.RouteNotConfigured.selector, CHAIN_B));
        a.router.swapAndBridge(address(a.alt), 1e18, 0, CHAIN_B, address(b.alt), finalReceiver, 0);
        vm.stopPrank();
    }
}
