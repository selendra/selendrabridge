// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {Gate} from "../src/Gate.sol";
import {GateProxy} from "../src/GateProxy.sol";
import {TestToken} from "../src/TestToken.sol";
import {BridgeHash} from "../src/BridgeHash.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @dev A gate as it was BEFORE the decimals revision, for upgrading away from.
///
///      The storage declarations are the current {Gate}'s, verbatim and in order,
///      up to `supportedChain` — and then `__gap[47]`, which is what occupied
///      slots 17-63 before `bridgeDecimalsOf` and `setupDeadline` were appended.
///      `test_Layout_LegacyPrefixMatchesTheCurrentGate` pins that against
///      `forge inspect`, so this fixture cannot quietly drift out of alignment
///      and start proving nothing.
///
///      Only the behaviour the migration test needs is implemented, and it is the
///      OLD behaviour: amounts are raw local units, with no conversion anywhere.
contract LegacyGate is Initializable, UUPSUpgradeable {
    using SafeERC20 for IERC20;

    address public owner;
    address public pendingOwner;
    mapping(address => bool) public isValidator;
    uint256 public validatorCount;
    uint256 public threshold;
    bytes32 public bridgeDomain;
    bool public paused;
    address public guardian;
    mapping(uint256 => uint256) public nonceTo;
    mapping(bytes32 => address) public sentBy;
    mapping(bytes32 => bool) public refunded;
    mapping(bytes32 => bool) public executed;
    mapping(bytes32 => bool) public cancelled;
    mapping(bytes32 => address) public tokenOf;
    mapping(address => uint256) public upgradeReadyAt;
    mapping(bytes32 => uint256) public governanceReadyAt;
    bool public isSealed;
    mapping(uint256 => bool) public supportedChain;
    uint256[47] private __gap;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address[] memory validators, uint256 threshold_, bytes32 domain)
        external
        initializer
    {
        bridgeDomain = domain;
        owner = msg.sender;
        for (uint256 i = 0; i < validators.length; i++) {
            isValidator[validators[i]] = true;
            validatorCount++;
        }
        threshold = threshold_;
    }

    function setLocalToken(bytes32 debridgeId, address localToken) external {
        require(msg.sender == owner, "owner");
        tokenOf[debridgeId] = localToken;
    }

    function seal() external {
        require(msg.sender == owner, "owner");
        isSealed = true;
    }

    /// @dev The legacy wire format: the RAW local amount, unconverted.
    function send(address token, uint256 amount, uint256 chainIdTo, bytes calldata receiver)
        external
        returns (bytes32 submissionId)
    {
        uint256 nonce = nonceTo[chainIdTo]++;
        bytes32 debridgeId = BridgeHash.getDebridgeId(block.chainid, token);
        submissionId = BridgeHash.getSubmissionId(
            bridgeDomain, debridgeId, amount, block.chainid, chainIdTo, nonce, receiver
        );
        sentBy[submissionId] = msg.sender;
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
    }

    function _authorizeUpgrade(address) internal view override {
        require(msg.sender == owner, "owner");
    }
}

/// @notice M-2: upgrading a pre-decimals gate IN PLACE, which is the model the
///         contract's own header commits to ("Upgrading in place keeps one
///         address and one storage, which removes the need to ever redeploy").
///
///         The audit found that the decimals revision broke it: on the block the
///         new implementation landed, `bridgeDecimalsOf` and `supportedChain` read
///         zero, so `send` reverted `UnsupportedChain`, `claim` reverted
///         `BridgeDecimalsUnset` — and so did `refund`, the one path documented as
///         never halting, which left the two-phase recovery unable to rescue what
///         the frozen claim had stranded. Then, once decimals were registered, a
///         pre-upgrade in-flight id (carrying a LOCAL amount) was read as a WIRE
///         amount and paid a power of ten too much.
contract MigrationV2Test is Test {
    uint256 constant CHAIN_SRC = 1337;
    uint256 constant CHAIN_DST = 1338;
    bytes32 constant DOMAIN = keccak256("mesh.legacy.generation");

    uint256 v1pk = 0xA11CE;
    address v1;
    address user = address(0xB0B);
    address receiverAddr = address(0xCAFE);

    LegacyGate legacy;
    TestToken token;
    bytes receiver;

    function setUp() public {
        vm.chainId(CHAIN_SRC);
        v1 = vm.addr(v1pk);
        receiver = abi.encodePacked(receiverAddr);

        address[] memory vals = new address[](1);
        vals[0] = v1;
        GateProxy proxy = new GateProxy(
            address(new LegacyGate()), abi.encodeCall(LegacyGate.initialize, (vals, 1, DOMAIN))
        );
        legacy = LegacyGate(address(proxy));

        token = new TestToken("Test", "TST"); // 18 decimals
        token.mint(user, 1_000 ether);
        token.mint(address(legacy), 1_000 ether); // destination-side liquidity
        vm.prank(user);
        token.approve(address(legacy), type(uint256).max);
        legacy.seal();
    }

    function _sign(bytes32 id) internal view returns (bytes[] memory sigs) {
        (uint8 vv, bytes32 r, bytes32 s) = vm.sign(v1pk, MessageHashUtils.toEthSignedMessageHash(id));
        sigs = new bytes[](1);
        sigs[0] = abi.encodePacked(r, s, vv);
    }

    /// A transfer locked under the OLD rules: `amount` is raw local units.
    function _legacyInFlight(uint256 localAmount) internal returns (bytes32 id) {
        vm.prank(user);
        id = legacy.send(address(token), localAmount, CHAIN_DST, receiver);
    }

    function _upgradeTo(address impl, bytes memory data) internal {
        UUPSUpgradeable(address(legacy)).upgradeToAndCall(impl, data);
    }

    function _tokens() internal view returns (address[] memory t) {
        t = new address[](1);
        t[0] = address(token);
    }

    function _chains() internal pure returns (uint256[] memory c) {
        c = new uint256[](1);
        c[0] = CHAIN_DST;
    }

    // -----------------------------------------------------------------
    // the fixture has to actually be the old layout
    // -----------------------------------------------------------------

    /// Slots 0-16 must mean the same thing in both contracts, or every test here
    /// is upgrading onto storage that was never the shape being claimed.
    function test_Layout_LegacyPrefixMatchesTheCurrentGate() public {
        // Values written through the LEGACY implementation...
        bytes32 did = BridgeHash.getDebridgeId(CHAIN_SRC, address(token));
        legacy.setLocalToken(did, address(token));
        bytes32 id = _legacyInFlight(10 ether);

        _upgradeTo(address(new Gate()), "");
        Gate upgraded = Gate(address(legacy));

        // ...must read back identically through the NEW one.
        assertEq(upgraded.owner(), address(this), "owner slot 0");
        assertEq(upgraded.bridgeDomain(), DOMAIN, "bridgeDomain slot 5");
        assertEq(upgraded.threshold(), 1, "threshold slot 4");
        assertEq(upgraded.validatorCount(), 1, "validatorCount slot 3");
        assertTrue(upgraded.isValidator(v1), "isValidator slot 2");
        assertEq(upgraded.nonceTo(CHAIN_DST), 1, "nonceTo slot 7");
        assertEq(upgraded.sentBy(id), user, "sentBy slot 8");
        assertEq(upgraded.tokenOf(did), address(token), "tokenOf slot 12");
        assertTrue(upgraded.isSealed(), "isSealed slot 15");

        // And the newly appended slots must be untouched virgin storage.
        assertEq(upgraded.setupDeadline(), 0, "setupDeadline was gap");
        (bool set,,) = upgraded.bridgeDecimalsOf(address(token));
        assertFalse(set, "bridgeDecimalsOf was gap");
    }

    // -----------------------------------------------------------------
    // the break, and what is left of it
    // -----------------------------------------------------------------

    /// Without the migration call the gate is still stopped for `claim` and
    /// `send` — an operator MUST seed the new state. What must NOT happen is the
    /// recovery path stopping with it: `refund` is documented as never halting,
    /// and before this fix it reverted `BridgeDecimalsUnset` like everything else,
    /// so funds frozen by the upgrade could not even be returned.
    function test_UpgradeWithoutMigration_StillRefunds() public {
        bytes32 did = BridgeHash.getDebridgeId(CHAIN_SRC, address(token));
        bytes32 id = _legacyInFlight(10 ether);
        uint256 balanceBefore = token.balanceOf(user);

        _upgradeTo(address(new Gate()), "");
        Gate upgraded = Gate(address(legacy));

        // The forward paths are stopped, loudly, which is the operator's cue.
        vm.expectRevert(abi.encodeWithSelector(Gate.UnsupportedChain.selector, CHAIN_DST));
        vm.prank(user);
        upgraded.send(address(token), 1 ether, CHAIN_DST, receiver, "");

        // The way back is NOT stopped: an unregistered token can only mean a
        // legacy lock, whose amount was already local units.
        bytes32 refundId = BridgeHash.getRefundId(id);
        upgraded.refund(
            address(token), did, 10 ether, CHAIN_DST, 0, receiver, "", "", _sign(refundId)
        );
        assertEq(token.balanceOf(user), balanceBefore + 10 ether, "refund pays exactly what was locked");
        assertTrue(upgraded.refunded(id), "and is marked spent");
    }

    /// The whole point of {initializeV2}: seeded in the SAME transaction as the
    /// implementation swap, so there is no block in which the gate is installed
    /// and its state is missing.
    function test_UpgradeAndCall_LeavesNoBrokenBlock() public {
        bytes32 did = BridgeHash.getDebridgeId(CHAIN_SRC, address(token));
        legacy.setLocalToken(did, address(token));

        _upgradeTo(
            address(new Gate()), abi.encodeCall(Gate.initializeV2, (_tokens(), _chains()))
        );
        Gate upgraded = Gate(address(legacy));

        // Identity scale: registered, and a no-op conversion.
        (bool set, uint8 bridgeDec, uint8 localDec) = upgraded.bridgeDecimalsOf(address(token));
        assertTrue(set, "registered");
        assertEq(bridgeDec, 18, "identity");
        assertEq(localDec, 18, "identity");
        assertEq(upgraded.bridgeUnit(address(token)), 1, "conversion is a no-op");
        assertTrue(upgraded.supportedChain(CHAIN_DST), "destination relisted");

        // Both directions work again, in the same units as before the upgrade.
        vm.prank(user);
        upgraded.send(address(token), 5 ether, CHAIN_DST, receiver, "");

        vm.chainId(CHAIN_DST);
        bytes32 inbound = upgraded.computeSubmissionId(did, 7 ether, CHAIN_SRC, CHAIN_DST, 99, receiver, "", "");
        upgraded.claim(did, 7 ether, CHAIN_SRC, 99, receiver, "", "", _sign(inbound));
        assertEq(token.balanceOf(receiverAddr), 7 ether, "claim pays the raw amount, as it always did");
    }

    /// The silent half of M-2, and the reason the migration registers IDENTITY
    /// rather than the mesh's real scale: a pre-upgrade id carries a local amount,
    /// and any non-identity scale multiplies it on the way out.
    function test_Migration_IdentityIsWhatStopsThePowerOfTenOverpay() public {
        bytes32 did = BridgeHash.getDebridgeId(CHAIN_SRC, address(token));
        legacy.setLocalToken(did, address(token));

        // An id created under the OLD rules: 3 TST as 3e18 raw units.
        vm.chainId(CHAIN_DST);
        bytes32 inflight =
            BridgeHash.getSubmissionId(DOMAIN, did, 3 ether, CHAIN_SRC, CHAIN_DST, 42, receiver);

        _upgradeTo(
            address(new Gate()), abi.encodeCall(Gate.initializeV2, (_tokens(), _chains()))
        );
        Gate upgraded = Gate(address(legacy));

        upgraded.claim(did, 3 ether, CHAIN_SRC, 42, receiver, "", "", _sign(inflight));
        assertEq(token.balanceOf(receiverAddr), 3 ether, "exactly what it always meant");

        // Had the mesh's real scale (6) been registered instead, the same claim
        // would have released 3e18 * 1e12 — a trillion-fold overpay that the
        // gate's whole liquidity could not cover. The registration is write-once,
        // so identity is now permanent for this gate: re-scaling a live asset is
        // a new deployment generation, never an upgrade.
        vm.expectRevert(abi.encodeWithSelector(Gate.BridgeDecimalsAlreadySet.selector, address(token)));
        upgraded.setBridgeDecimals(address(token), 6);
    }

    // -----------------------------------------------------------------
    // the migration entrypoint itself
    // -----------------------------------------------------------------

    function test_InitializeV2_RunsOnceAndOnlyForTheOwner() public {
        address impl = address(new Gate());

        // A stranger cannot ride the upgrade call.
        vm.prank(address(0xBAD));
        vm.expectRevert("owner"); // legacy _authorizeUpgrade
        _upgradeTo(impl, abi.encodeCall(Gate.initializeV2, (_tokens(), _chains())));

        _upgradeTo(impl, abi.encodeCall(Gate.initializeV2, (_tokens(), _chains())));
        Gate upgraded = Gate(address(legacy));

        // Not a second time, by anyone.
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        upgraded.initializeV2(_tokens(), _chains());
    }

    /// Idempotent over its inputs: a token that is already registered keeps the
    /// scale it has, so re-running a migration list cannot silently re-scale an
    /// asset that was set correctly.
    function test_InitializeV2_SkipsWhatIsAlreadyRegistered() public {
        address[] memory two = new address[](2);
        two[0] = address(token);
        two[1] = address(token); // same token twice
        uint256[] memory chains = _chains();

        _upgradeTo(address(new Gate()), abi.encodeCall(Gate.initializeV2, (two, chains)));
        Gate upgraded = Gate(address(legacy));
        (bool set, uint8 bridgeDec,) = upgraded.bridgeDecimalsOf(address(token));
        assertTrue(set);
        assertEq(bridgeDec, 18, "still identity, not re-written");
    }

    function test_InitializeV2_RefusesTheZeroToken() public {
        address[] memory bad = new address[](1);
        bad[0] = address(0);
        vm.expectRevert(Gate.ZeroAddress.selector);
        _upgradeTo(address(new Gate()), abi.encodeCall(Gate.initializeV2, (bad, _chains())));
    }

    /// A gate migrated in place does NOT get a fresh instant-registration window:
    /// `setupDeadline` was gap, so it reads zero and every registration takes the
    /// public delay. Fail-closed is the right default for a gate that already
    /// holds funds (M-1 + M-2 together).
    function test_MigratedGate_GetsNoFreshSetupPhase() public {
        _upgradeTo(address(new Gate()), abi.encodeCall(Gate.initializeV2, (_tokens(), _chains())));
        Gate upgraded = Gate(address(legacy));

        assertFalse(upgraded.inSetupPhase(), "no instant window");
        bytes32 did = BridgeHash.getDebridgeId(CHAIN_SRC, address(0xFEED));
        bytes32 action = upgraded.setLocalTokenActionId(did, address(token));
        vm.expectRevert(abi.encodeWithSelector(Gate.GovernanceNotScheduled.selector, action));
        upgraded.setLocalToken(did, address(token));
    }
}
