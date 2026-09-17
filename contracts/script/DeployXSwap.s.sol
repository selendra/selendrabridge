// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {SwapPool} from "../src/SwapPool.sol";
import {Gate} from "../src/Gate.sol";
import {GateDeployer} from "../src/GateDeployer.sol";
import {SwapRouter} from "../src/SwapRouter.sol";
import {BridgeHash} from "../src/BridgeHash.sol";

/// @dev Mintable ERC-20 with configurable decimals.
contract XMintable is ERC20 {
    uint8 private immutable _dec;

    constructor(string memory n, string memory s, uint8 d) ERC20(n, s) {
        _dec = d;
    }

    function decimals() public view override returns (uint8) {
        return _dec;
    }

    function mint(address to, uint256 amt) external {
        _mint(to, amt);
    }
}

/// @notice Deploy ONE chain's cross-chain-swap stack: a 6-dec stable hub, one
///         18-dec alt token, a seeded SwapPool, a Gate (single validator), and a
///         SwapRouter wired to both. Writes fixtures/xswap-<chainid>.env.
///
///         Two steps, because a corridor needs the PEER's addresses:
///
///           1. `run()` on each chain — deploys, and registers the stable's
///              bridge decimals (without them `Gate.send`, and so every
///              `swapAndBridge`, reverts with `BridgeDecimalsUnset`).
///              Env in: VALIDATOR (address), ALT_PRICE (uint, PRICE_ONE-scaled),
///                      ALT_SYMBOL (string).
///           2. `wire(...)` on each chain once both exist — lists the peer chain,
///              points the router at the peer router, maps the peer's stable to
///              the local one, and SEALS the gate (H-1: wire, seal, then fund):
///
///              forge script script/DeployXSwap.s.sol:DeployXSwap --broadcast \
///                --sig "wire(address,address,address,uint256,address,address)" \
///                $GATE $ROUTER $STABLE $PEER_CHAIN_ID $PEER_STABLE $PEER_ROUTER
///
///         Before this split the script wrote a stack that reverted on its first
///         `swapAndBridge`, and every step above lived only in `xswap.sh`.
contract DeployXSwap is Script {
    uint16 constant DEVIATION_BPS = 1000;
    /// @dev The demo stable is 6 decimals on every chain and bridges at full
    ///      precision. Every gate on a corridor must register the SAME value.
    uint8 public constant STABLE_BRIDGE_DECIMALS = 6;

    struct Params {
        address validator;
        uint256 altPrice;
        string altSymbol;
        /// @dev who ends up holding the seed tokens before they are deposited:
        ///      the broadcaster in a script, the script contract in a test.
        address funder;
    }

    struct Stack {
        XMintable usd;
        XMintable alt;
        SwapPool pool;
        Gate gate;
        SwapRouter router;
    }

    function run() external {
        Params memory p = Params({
            validator: vm.envAddress("VALIDATOR"),
            altPrice: vm.envUint("ALT_PRICE"),
            altSymbol: vm.envString("ALT_SYMBOL"),
            funder: msg.sender
        });

        vm.startBroadcast();
        Stack memory s = _deploy(p);
        vm.stopBroadcast();

        string memory env = string.concat(
            "STABLE=", vm.toString(address(s.usd)), "\n",
            "ALT=", vm.toString(address(s.alt)), "\n",
            "POOL=", vm.toString(address(s.pool)), "\n",
            "GATE=", vm.toString(address(s.gate)), "\n",
            "ROUTER=", vm.toString(address(s.router)), "\n"
        );
        vm.writeFile(string.concat("fixtures/xswap-", vm.toString(block.chainid), ".env"), env);

        console2.log("chain   :", block.chainid);
        console2.log("stable  :", address(s.usd));
        console2.log("alt     :", address(s.alt));
        console2.log("pool    :", address(s.pool));
        console2.log("gate    :", address(s.gate));
        console2.log("router  :", address(s.router));
        console2.log("next    : wire(...) on both chains; the gate is unsealed until then");
    }

    /// @notice Step 2 — see the contract docs.
    function wire(
        address gate,
        address router,
        address stable,
        uint256 peerChainId,
        address peerStable,
        address peerRouter
    ) external {
        vm.startBroadcast();
        _wire(Gate(gate), SwapRouter(router), stable, peerChainId, peerStable, peerRouter);
        vm.stopBroadcast();
        console2.log("wired + sealed gate", gate, "for peer chain", peerChainId);
    }

    /// @dev Deploy + per-chain configuration. Public so tests can run it; the
    ///      caller (broadcaster or test) becomes the owner of every contract.
    function _deploy(Params memory p) public returns (Stack memory s) {
        s.usd = new XMintable("USD", "USD", 6);
        s.alt = new XMintable(p.altSymbol, p.altSymbol, 18);

        s.pool = new SwapPool(address(s.usd), DEVIATION_BPS);
        s.pool.listToken(address(s.alt), p.altPrice);
        _seed(s.pool, s.usd, 10_000_000e6, p.funder);
        _seed(s.pool, s.alt, 1_000_000e18, p.funder);

        address[] memory vals = new address[](1);
        vals[0] = p.validator;
        // Local bring-up script: a fixed demo domain is fine here because
        // nothing it deploys shares a validator set with a real mesh.
        s.gate = GateDeployer.deploy(vals, 1, keccak256("selendra.bridge.xswap.demo"));
        // Needed on BOTH ends: the source converts the send with it, the
        // destination the claim. Write-once, and instant only while unsealed.
        s.gate.setBridgeDecimals(address(s.usd), STABLE_BRIDGE_DECIMALS);

        s.router = new SwapRouter(s.gate, s.pool);
    }

    /// @dev Cross-chain wiring for one side of the corridor, then seal. Public
    ///      for tests, like {_deploy}.
    function _wire(
        Gate gate,
        SwapRouter router,
        address stable,
        uint256 peerChainId,
        address peerStable,
        address peerRouter
    ) public {
        gate.setSupportedChain(peerChainId, true);
        router.setRemoteRouter(peerChainId, abi.encodePacked(peerRouter));
        // The stable arrives here as (native chain = peer, native token = peer
        // stable) and pays out the local stable.
        gate.setLocalToken(BridgeHash.getDebridgeId(peerChainId, peerStable), stable);
        gate.seal();
    }

    function _seed(SwapPool pool, XMintable token, uint256 amt, address funder) internal {
        token.mint(funder, amt);
        token.approve(address(pool), amt);
        pool.seedLiquidity(address(token), amt);
    }
}
