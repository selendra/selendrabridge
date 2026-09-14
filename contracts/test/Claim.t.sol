// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {Gate} from "../src/Gate.sol";
import {deployTestGate, TEST_BRIDGE_DOMAIN} from "./helpers/TestGate.sol";
import {TestToken} from "../src/TestToken.sol";
import {BridgeHash} from "../src/BridgeHash.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract ClaimTest is Test {
    Gate gate;
    TestToken token;

    // validator keypairs
    uint256 v1pk = 0xA11CE;
    uint256 v2pk = 0xB0B;
    uint256 v3pk = 0xC0FFEE;
    uint256 strangerPk = 0xBADBAD;

    address v1;
    address v2;
    address v3;

    address receiverAddr = address(0xCAFE);

    bytes32 debridgeId;
    uint256 constant AMOUNT = 100 ether;
    uint256 constant CHAIN_FROM = 1337;
    uint256 constant NONCE = 0;
    bytes receiver;
    bytes EMPTY_AUTO = "";
    bytes EMPTY_SENDER = "";

    function setUp() public {
        v1 = vm.addr(v1pk);
        v2 = vm.addr(v2pk);
        v3 = vm.addr(v3pk);
        receiver = abi.encodePacked(receiverAddr);

        address[] memory validators = new address[](3);
        validators[0] = v1;
        validators[1] = v2;
        validators[2] = v3;
        gate = deployTestGate(validators, 1); // threshold 1 by default

        token = new TestToken("Test", "TST");
        gate.setBridgeDecimals(address(token), 18);
        // pre-fund the gate with target-side liquidity
        token.mint(address(gate), 1_000 ether);

        // register the asset: claims of `debridgeId` release `token`
        debridgeId = BridgeHash.getDebridgeId(CHAIN_FROM, address(0x1234));
        gate.setLocalToken(debridgeId, address(token));
    }

    // --- helpers ---

    function _id() internal view returns (bytes32) {
        return BridgeHash.getSubmissionId(
            TEST_BRIDGE_DOMAIN, debridgeId, AMOUNT, CHAIN_FROM, block.chainid, NONCE, receiver
        );
    }

    function _sign(uint256 pk, bytes32 submissionId) internal pure returns (bytes memory) {
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(submissionId);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @dev sort two signatures by recovered signer ascending (claim requires it)
    function _sortedTwo(uint256 pkA, uint256 pkB, bytes32 submissionId)
        internal
        returns (bytes[] memory sigs)
    {
        sigs = new bytes[](2);
        if (vm.addr(pkA) < vm.addr(pkB)) {
            sigs[0] = _sign(pkA, submissionId);
            sigs[1] = _sign(pkB, submissionId);
        } else {
            sigs[0] = _sign(pkB, submissionId);
            sigs[1] = _sign(pkA, submissionId);
        }
    }

    function _claim(bytes[] memory sigs) internal returns (bytes32) {
        return gate.claim(
            debridgeId, AMOUNT, CHAIN_FROM, NONCE, receiver, EMPTY_AUTO, EMPTY_SENDER, sigs
        );
    }

    // --- tests ---

    function test_Claim_RevertsTooManySignatures() public {
        // validatorCount is 3; a 4-signature array is junk padding and must revert
        // (the cap is checked before any ECDSA recovery, so contents don't matter).
        bytes32 id = _id();
        bytes[] memory sigs = new bytes[](4);
        sigs[0] = _sign(v1pk, id);
        sigs[1] = _sign(v2pk, id);
        sigs[2] = _sign(v3pk, id);
        sigs[3] = _sign(v1pk, id);
        vm.expectRevert(abi.encodeWithSelector(Gate.TooManySignatures.selector, 4, 3));
        _claim(sigs);
    }

    function test_Claim_HappyPath_OneSig() public {
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(v1pk, _id());

        uint256 before = token.balanceOf(receiverAddr);
        bytes32 id = _claim(sigs);

        assertEq(token.balanceOf(receiverAddr), before + AMOUNT, "receiver not paid");
        assertTrue(gate.executed(id), "executed flag not set");
    }

    function test_Claim_Replay_Reverts() public {
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(v1pk, _id());
        _claim(sigs);

        vm.expectRevert(Gate.AlreadyExecuted.selector);
        _claim(sigs);
    }

    function test_Claim_InsufficientSigs_Reverts() public {
        gate.setThreshold(2);
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(v1pk, _id());

        vm.expectRevert(abi.encodeWithSelector(Gate.NotEnoughSignatures.selector, 1, 2));
        _claim(sigs);
    }

    function test_Claim_TwoOfTwo_Succeeds() public {
        gate.setThreshold(2);
        bytes[] memory sigs = _sortedTwo(v1pk, v2pk, _id());

        _claim(sigs);
        assertEq(token.balanceOf(receiverAddr), AMOUNT);
    }

    function test_Claim_BadSigner_Reverts() public {
        // a non-validator signs; count stays 0 < threshold 1
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(strangerPk, _id());

        vm.expectRevert(abi.encodeWithSelector(Gate.NotEnoughSignatures.selector, 0, 1));
        _claim(sigs);
    }

    function test_Claim_DuplicateSigner_Reverts() public {
        // same validator twice: not strictly ascending => InvalidSignerOrder
        gate.setThreshold(2);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(v1pk, _id());
        sigs[1] = _sign(v1pk, _id());

        vm.expectRevert(Gate.InvalidSignerOrder.selector);
        _claim(sigs);
    }

    function test_Claim_TamperedAmount_Reverts() public {
        // validator signs the real id, but caller submits a different amount =>
        // recomputed id differs => signature recovers a different/garbage signer.
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(v1pk, _id());

        // amount tampered to 999 ether; recomputed id won't match the signed one
        vm.expectRevert(abi.encodeWithSelector(Gate.NotEnoughSignatures.selector, 0, 1));
        gate.claim(
            debridgeId, 999 ether, CHAIN_FROM, NONCE, receiver, EMPTY_AUTO, EMPTY_SENDER, sigs
        );
    }

    function test_Claim_UnknownAsset_Reverts() public {
        bytes32 unknown = BridgeHash.getDebridgeId(CHAIN_FROM, address(0xDEAD));
        bytes32 id = BridgeHash.getSubmissionId(
            TEST_BRIDGE_DOMAIN, unknown, AMOUNT, CHAIN_FROM, block.chainid, NONCE, receiver
        );
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(v1pk, id);

        vm.expectRevert(abi.encodeWithSelector(Gate.UnknownAsset.selector, unknown));
        gate.claim(unknown, AMOUNT, CHAIN_FROM, NONCE, receiver, EMPTY_AUTO, EMPTY_SENDER, sigs);
    }
}
