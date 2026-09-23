// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {BridgeHash} from "../src/BridgeHash.sol";

/// @notice Generates submissionId fixtures shared with the Rust side (Phase 3).
///         Run with: forge test --match-contract GenFixtures
///         Writes fixtures/submission_ids.json (inputs + Solidity-computed ids).
///         The Rust test (bridge-core) reads this file and must recompute every id.
contract GenFixturesTest is Test {
    struct F {
        string name;
        bytes32 bridgeDomain;
        bytes32 debridgeId;
        uint8 bridgeDecimals;
        uint256 amount;
        uint256 chainIdFrom;
        uint256 chainIdTo;
        uint256 nonce;
        bytes receiver;
        bool hasAuto;
        uint256 executionFee;
        uint256 flags;
        bytes fallbackAddress;
        bytes data;
        bytes nativeSender;
    }

    function _id(F memory f) internal pure returns (bytes32) {
        if (!f.hasAuto) {
            return BridgeHash.getSubmissionId(
                f.bridgeDomain,
                f.debridgeId,
                f.bridgeDecimals,
                f.amount,
                f.chainIdFrom,
                f.chainIdTo,
                f.nonce,
                f.receiver
            );
        }
        return BridgeHash.getSubmissionIdWithAuto(
            f.bridgeDomain,
            f.debridgeId,
            f.bridgeDecimals,
            f.amount,
            f.chainIdFrom,
            f.chainIdTo,
            f.nonce,
            f.receiver,
            BridgeHash.AutoParams({
                executionFee: f.executionFee,
                flags: f.flags,
                fallbackAddress: f.fallbackAddress,
                data: f.data,
                nativeSender: f.nativeSender
            })
        );
    }

    function _obj(F memory f) internal pure returns (string memory) {
        return string.concat(
            "{",
            '"name":"', f.name, '",',
            '"bridgeDomain":"', vm.toString(f.bridgeDomain), '",',
            '"debridgeId":"', vm.toString(f.debridgeId), '",',
            '"bridgeDecimals":', vm.toString(uint256(f.bridgeDecimals)), ",",
            '"amount":"', vm.toString(f.amount), '",',
            '"chainIdFrom":', vm.toString(f.chainIdFrom), ",",
            '"chainIdTo":', vm.toString(f.chainIdTo), ",",
            '"nonce":', vm.toString(f.nonce), ",",
            '"receiver":"', vm.toString(f.receiver), '",',
            '"hasAuto":', f.hasAuto ? "true" : "false", ",",
            '"executionFee":"', vm.toString(f.executionFee), '",',
            '"flags":"', vm.toString(f.flags), '",',
            '"fallbackAddress":"', vm.toString(f.fallbackAddress), '",',
            '"data":"', vm.toString(f.data), '",',
            '"nativeSender":"', vm.toString(f.nativeSender), '",',
            '"submissionId":"', vm.toString(_id(f)), '",',
            // The cancel/refund attestation digests derived from the same id, so
            // the Rust side is locked to Solidity for those domains too.
            '"cancelId":"', vm.toString(BridgeHash.getCancelId(_id(f))), '",',
            '"refundId":"', vm.toString(BridgeHash.getRefundId(_id(f))), '"',
            "}"
        );
    }

    /// @dev Two distinct deployment generations. Fixtures 1-3 use A; fixture 4
    ///      repeats fixture 1 verbatim under B, so any implementation that
    ///      ignores the domain produces two identical ids and fails parity.
    bytes32 constant DOMAIN_A = keccak256("selendra.bridge.mesh.v1");
    bytes32 constant DOMAIN_B = keccak256("selendra.bridge.mesh.v2");

    function test_WriteFixtures() public {
        F[] memory fs = new F[](5);

        // 1) plain transfer, no execution payload, EVM 20-byte receiver
        fs[0] = F({
            name: "no-auto",
            bridgeDomain: DOMAIN_A,
            debridgeId: BridgeHash.getDebridgeId(1337, address(0x1234)),
            bridgeDecimals: 18,
            amount: 100 ether,
            chainIdFrom: 1337,
            chainIdTo: 1338,
            nonce: 0,
            receiver: abi.encodePacked(address(0xCAFE)),
            hasAuto: false,
            executionFee: 0,
            flags: 0,
            fallbackAddress: "",
            data: "",
            nativeSender: ""
        });

        // 2) transfer WITH an execution payload
        fs[1] = F({
            name: "with-auto",
            bridgeDomain: DOMAIN_A,
            debridgeId: BridgeHash.getDebridgeId(1337, address(0xABCD)),
            bridgeDecimals: 6,
            amount: 5_000_000,
            chainIdFrom: 1337,
            chainIdTo: 56,
            nonce: 7,
            receiver: abi.encodePacked(address(0xBEEF)),
            hasAuto: true,
            executionFee: 1 ether,
            flags: 2,
            fallbackAddress: abi.encodePacked(address(0xF00D)),
            data: hex"deadbeef0102",
            nativeSender: abi.encodePacked(address(0x5151))
        });

        // 3) non-EVM-shaped 32-byte receiver, large nonce/amount, no auto
        fs[2] = F({
            name: "long-receiver",
            bridgeDomain: DOMAIN_A,
            debridgeId: BridgeHash.getDebridgeId(10, address(0x9999)),
            bridgeDecimals: 0,
            amount: type(uint256).max,
            chainIdFrom: 10,
            chainIdTo: 7565164, // Solana-style large chain id
            nonce: 123456789,
            receiver: hex"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            hasAuto: false,
            executionFee: 0,
            flags: 0,
            fallbackAddress: "",
            data: "",
            nativeSender: ""
        });

        // 4) every field of fixture 1, under a DIFFERENT deployment domain. This is
        //    the H-3 regression at the hash layer: the ids must diverge, which is
        //    exactly what stops a previous deployment's attestations verifying
        //    against a redeployed mesh.
        //
        //    Spelled out rather than copied from fs[0]: memory struct assignment
        //    in Solidity aliases instead of copying, so `fs[3] = fs[0]` followed by
        //    a field write would silently rewrite fixture 1 and make both fixtures
        //    agree — the test would pass by destroying what it compares against.
        fs[3] = F({
            name: "domain-separated",
            bridgeDomain: DOMAIN_B,
            debridgeId: BridgeHash.getDebridgeId(1337, address(0x1234)),
            bridgeDecimals: 18,
            amount: 100 ether,
            chainIdFrom: 1337,
            chainIdTo: 1338,
            nonce: 0,
            receiver: abi.encodePacked(address(0xCAFE)),
            hasAuto: false,
            executionFee: 0,
            flags: 0,
            fallbackAddress: "",
            data: "",
            nativeSender: ""
        });

        // 5) every field of fixture 1, at a DIFFERENT wire scale. This is the H-2
        //    regression at the hash layer: one operator registering an asset at 17
        //    instead of 18 must make the ids diverge, because that is what stops
        //    the mis-scaled gate settling a transfer it would pay out 10x on.
        //    Spelled out rather than copied, for the aliasing reason above.
        fs[4] = F({
            name: "scale-separated",
            bridgeDomain: DOMAIN_A,
            debridgeId: BridgeHash.getDebridgeId(1337, address(0x1234)),
            bridgeDecimals: 17,
            amount: 100 ether,
            chainIdFrom: 1337,
            chainIdTo: 1338,
            nonce: 0,
            receiver: abi.encodePacked(address(0xCAFE)),
            hasAuto: false,
            executionFee: 0,
            flags: 0,
            fallbackAddress: "",
            data: "",
            nativeSender: ""
        });

        assertTrue(_id(fs[0]) != _id(fs[3]), "bridgeDomain must change the submissionId");
        assertTrue(_id(fs[0]) != _id(fs[4]), "bridgeDecimals must change the submissionId");

        string memory json = "{\"fixtures\":[";
        for (uint256 i = 0; i < fs.length; i++) {
            json = string.concat(json, _obj(fs[i]));
            if (i + 1 < fs.length) json = string.concat(json, ",");
        }
        json = string.concat(json, "]}");

        vm.writeFile("fixtures/submission_ids.json", json);

        // sanity: log the ids
        for (uint256 i = 0; i < fs.length; i++) {
            emit log_named_bytes32(fs[i].name, _id(fs[i]));
        }
    }
}
