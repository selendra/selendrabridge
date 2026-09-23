// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title BridgeHash
/// @notice Canonical, deterministic hashing for cross-chain messages.
/// @dev    Mirrors deBridge's scheme (debridge-contracts-v1 DeBridgeGate):
///         everything is `abi.encodePacked` so it can be reproduced byte-for-byte
///         off-chain with alloy's `abi_encode_packed` in the Rust validator/keeper.
///         THE HASH IS SACRED — Solidity and Rust must agree (Phase 3 test).
library BridgeHash {
    /// @dev domain-separating prefix, as in deBridge.
    uint256 internal constant SUBMISSION_PREFIX = 1;
    /// @dev domain prefix for a destination-side CANCEL attestation. A validator
    ///      signature over a cancelId authorises burning `executed[submissionId]`
    ///      on the target gate so the transfer can never be claimed.
    uint256 internal constant CANCEL_PREFIX = 2;
    /// @dev domain prefix for a source-side REFUND attestation. A validator
    ///      signature over a refundId authorises returning the locked funds to
    ///      the original sender on the source gate.
    uint256 internal constant REFUND_PREFIX = 3;

    /// @notice Optional execution payload attached to a transfer.
    /// @dev    `nativeSender` is meaningful only on the claim (From) side; on the
    ///         source side it is the packed msg.sender that the gate injects.
    struct AutoParams {
        uint256 executionFee;
        uint256 flags;
        bytes fallbackAddress;
        bytes data;
        bytes nativeSender;
    }

    /// @notice Asset id = keccak256(abi.encodePacked(nativeChainId, nativeToken)).
    function getDebridgeId(uint256 nativeChainId, address nativeToken)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(nativeChainId, nativeToken));
    }

    /// @dev The 9-field base of every submissionId, returned unhashed so the
    ///      auto-variant can append to it (exactly as deBridge does).
    ///
    /// @param bridgeDomain the DEPLOYMENT binding, and the whole reason this
    ///        differs from deBridge's layout. Without it a submissionId commits
    ///        only to (asset, chain pair, amount, receiver, nonce) — never to the
    ///        gates themselves — so every quorum signature from a previous
    ///        deployment stays valid against a freshly deployed gate on the same
    ///        chain pair, which also restarts `nonceTo` at 0. That was observed
    ///        draining a live redeployment: 3 stale attestations paid out against
    ///        deposits still locked in the superseded gate.
    ///
    ///        Every gate in ONE mesh generation shares ONE domain value, so ids
    ///        agree across chains; a new generation picks a new value, which
    ///        makes every historical attestation hash to something the new gates
    ///        never accept. A mismatched domain fails loudly (no id ever agrees)
    ///        rather than silently paying out, which is the failure mode you want.
    ///
    /// @param bridgeDecimals the SCALE `amount` is denominated in — H-2, and the
    ///        second reason this differs from deBridge's layout. `amount` is a
    ///        bare integer; what it is worth depends entirely on the wire scale
    ///        each end registered for the asset. Leaving that scale out of the
    ///        preimage made the two ends agreeing a pure off-chain convention:
    ///        a source registered at 6 and a destination at 3 produce the SAME
    ///        id for a transfer the destination then pays out 1000x, to any
    ///        user, permissionlessly, with nothing on-chain able to detect it.
    ///
    ///        With the scale inside the preimage, each gate hashes the value it
    ///        itself registered, so a mis-registration makes the ids diverge and
    ///        the claim simply never verifies. Same discipline as `bridgeDomain`:
    ///        a mesh-wide constant fails LOUDLY on mismatch rather than paying
    ///        out the wrong number.
    ///
    ///        One byte, packed between two fixed-width words, so it neither
    ///        widens the dynamic tail nor disturbs the length invariant the
    ///        no-auto/with-auto forms are distinguished by.
    function packedSubmission(
        bytes32 bridgeDomain,
        bytes32 debridgeId,
        uint8 bridgeDecimals,
        uint256 amount,
        uint256 chainIdFrom,
        uint256 chainIdTo,
        uint256 nonce,
        bytes memory receiver
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            SUBMISSION_PREFIX,
            bridgeDomain,
            debridgeId,
            chainIdFrom,
            chainIdTo,
            bridgeDecimals,
            amount,
            receiver,
            nonce
        );
    }

    /// @notice submissionId for a transfer WITHOUT an execution payload.
    function getSubmissionId(
        bytes32 bridgeDomain,
        bytes32 debridgeId,
        uint8 bridgeDecimals,
        uint256 amount,
        uint256 chainIdFrom,
        uint256 chainIdTo,
        uint256 nonce,
        bytes memory receiver
    ) internal pure returns (bytes32) {
        return keccak256(
            packedSubmission(
                bridgeDomain, debridgeId, bridgeDecimals, amount, chainIdFrom, chainIdTo, nonce, receiver
            )
        );
    }

    /// @notice submissionId for a transfer WITH an execution payload.
    function getSubmissionIdWithAuto(
        bytes32 bridgeDomain,
        bytes32 debridgeId,
        uint8 bridgeDecimals,
        uint256 amount,
        uint256 chainIdFrom,
        uint256 chainIdTo,
        uint256 nonce,
        bytes memory receiver,
        AutoParams memory autoParams
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                packedSubmission(
                    bridgeDomain, debridgeId, bridgeDecimals, amount, chainIdFrom, chainIdTo, nonce, receiver
                ),
                autoParams.executionFee,
                autoParams.flags,
                keccak256(autoParams.fallbackAddress),
                keccak256(autoParams.data),
                keccak256(autoParams.nativeSender)
            )
        );
    }

    /// @notice Digest a validator signs to authorise CANCELLING a transfer on the
    ///         destination chain (burning it so `claim` can never release funds).
    /// @dev    Domain-separated from a submissionId two ways: a different prefix,
    ///         and a 64-byte preimage where a submissionId's is >= 225 bytes. So a
    ///         validator's transfer signature can never be replayed as a cancel
    ///         (and vice-versa) short of a keccak256 preimage collision.
    function getCancelId(bytes32 submissionId) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(CANCEL_PREFIX, submissionId));
    }

    /// @notice Digest a validator signs to authorise REFUNDING a cancelled
    ///         transfer on the source chain. Domain-separated exactly as
    ///         {getCancelId} is, so a cancel attestation can never be replayed as
    ///         a refund authorisation — the two are independent quorums.
    function getRefundId(bytes32 submissionId) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(REFUND_PREFIX, submissionId));
    }
}
