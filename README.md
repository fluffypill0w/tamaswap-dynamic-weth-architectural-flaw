# Architectural Flaw Report: Input Validation Failure & System Boundary Defects

**A security research case study isolating an input validation failure and integration vulnerability within the TamaSwap router reference blueprint on Ethereum Mainnet.** 

| Metadata | Details |
| :--- | :--- |
| **Target Architecture** | TamaSwap router reference blueprint (`src/TamaRouter.sol`) |
| **Repository Source** | `https://github.com/Bacon-labs/tamaswap/tree/main` |
| **Target Commit Hash** | `1777b7801562c8a734f675f60e387dc375d37439` |
| **Vulnerability Class** | Lack of input validation / missing invariant enforcement (untrusted WETH input) |
| **Impact** | Arbitrary asset redirection, system boundary defeat, localized DoS |
| **Status** | Unpatched (maintainer notified July 2026 at `hello[@]baconlabs.xyz`; unresponsive >90 days) |

---

### 1. Vulnerability Breakdown
Standard AMM configurations isolate core liquidity invariants inside pool contracts and utilize peripheral router contracts to handle messy user capital abstractions (like wrapping/unwrapping native assets). While `TamaSwap` focuses its formal verification rigor exclusively on its core contracts, it provides `TamaRouter.sol` as an unverified peripheral reference template to manage multi-hop swaps.

This peripheral template introduces a critical trust boundary defect by exposing the canonical wrapping gateway address dynamically via a client-supplied parameter (`address weth`):

```solidity
function swapETHForExactTokens(
    address weth, // <--- untrusted dynamic parameter
    uint256 amountOut,
    address[] calldata path,
    address to,
    uint256 deadline
) external payable ensure(deadline) returns (uint256[] memory amounts) {
    require(path.length >= 2, "TamaRouter: INVALID_PATH");
    require(path[0] == weth, "TamaRouter: INVALID_PATH");
    amounts = getAmountsIn(amountOut, path);
    require(amounts[0] <= msg.value, "TamaRouter: EXCESSIVE_INPUT_AMOUNT");
    _depositWrappedNative(weth, amounts[0]); // <--- escrows native ETH into untrusted contract
    _safeTransfer(weth, pairFor(path[0], path[1]), amounts[0]); // <--- routes based on untrusted topology
    _swap(amounts, path, to);
    if (msg.value > amounts[0]) _safeTransferETH(msg.sender, msg.value - amounts[0]);
}

function _depositWrappedNative(address weth, uint256 value) internal {
    require(weth.code.length > 0, "TamaRouter: NON_CONTRACT_WETH");
    IWrappedNativeMinimal(weth).deposit{value: value}(); // <--- Surrenders control flow via high-level call
}
```

Because the router lacks an asset whitelist assertion (`require(weth == CANONICAL_WETH)`), an execution path can completely dictate where native user or automated searcher capital is escrowed by establishing a custom token topology.


---


### 2. Threat Modeling

#### 2.1 The Dynamic Integration Honeypot Vector
While standard web interfaces screen unverified pools, algorithmic long-tail searchers query factory registries directly on-chain. This structural defect permits capital-efficient targeting of automated routing scripts:

1. **Pool Seeding:** An attacker registers a pool pairing an active secondary asset against a malicious ERC-20 token mimicking `WETH` that contains custom transfer hooks.
2. **Arbitrage Baiting:** The attacker manipulates pool reserves to create an attractive price imbalance.
3. **Execution Interception:** When a dynamic routing engine attempts to clear the path, it extracts the pair topology, identifies the fake wrapper as `token0`, and structures the transaction payload. Because the router explicitly forces `path[0] == weth`, it validates the untrusted address, processes the swap leg, and routes incoming native capital directly into the attacker's contract.

*Note on Execution Scope:* The vector itself is a universal structural flaw affecting any dynamic integration layer. The PoC in this repository is intentionally simplified to demonstrate the validation defect under a sequential frame. If an execution engine structures both legs atomically, the simulated trap will trigger a complete EVM state rollback, negating capital capture but executing a Denial-of-Service/Gas Griefing attack against the caller.

Characterizing the exact state transition constraints required to intercept highly optimized, atomic private RPC multi-bundle execution environments falls outside the scope of this repository, which focuses strictly on validating the underlying architectural flaw.

*Note on Execution Limits:* Static arbitrage scripts are immune because they are hardcoded to expect exactly four inputs based on the standard Uniswap V2 function signature. Because `TamaRouter` appends a non-standard fifth parameter (`address weth`), an automated script cannot map the data structure correctly, triggering an immediate transaction rejection.

Institutional MEV engines are also insulated by hardcoded canonical address whitelists within their private simulation pipelines. Consequently, the threat isolates to generalized routing engines, cross-chain aggregators, or dynamic multi-token search protocols that rely on runtime ABI parsing to resolve non-standard topologies.

#### 2.2 Simulation Divergence & Gas Exhaustion
* **Simulation Divergence:** Malicious wrapper variants can execute context-sensitive logic (e.g., branching behavior via `block.number` or `tx.origin`). This allows trades to simulate successfully inside off-chain sandboxes but enforce honeypot restrictions live on-chain.
* **Gas Exhaustion (Griefing):** Arbitrary target endpoints permit execution redirection into heavy state operations or gas-consuming loops mid-swap, introducing localized Denial-of-Service vectors against execution engines.

#### 2.3 Broken Trust Boundaries & Client-Side Reliance
By exposing core protocol invariants as runtime parameters, the contract design shifts security reliance entirely onto upstream, client-side sanitization (frontends, aggregators, or RPC providers). Smart contract architectures must maintain internal invariant enforcement independent of upstream client validation.


---


### 3. Case Study: The Limits of Formal Verification
The protocol was publicly marketed as "provably unhackable" based on formal verification proofs compiled in Lean. This vulnerability demonstrates a classic system boundary failure mode in automated auditing:

* **Property Mis-specification:** Formal verification tools only check if code adheres to defined mathematical properties. If the specification checks that pool math (x * y = k) is sound but omits properties enforcing asset invariants at the execution interface, the verification engine will pass structurally unsafe configurations as mathematically valid.
* **Takeaway:** Mathematical correctness at the token-pool layer does not guarantee game-theoretic or structural security at the routing layer.


---


### 4. Remediation
Expose `WETH` as a contract-level `immutable` state variable assigned at deployment, and remove the dynamic input parameter from all native entry pathways.

```solidity
contract TamaRouter {
    address public immutable WETH;

    constructor(address _weth) {
        WETH = _weth;
    }

    function swapETHForExactTokens(
        uint256 amountOut,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external payable ensure(deadline) returns (uint256[] memory amounts) {
        require(path[0] == WETH, "TamaRouter: INVALID_PATH");
        // ...
    }
}
```


---


## Installation & Execution

This repository isolates the PoC test suite within a minimal framework layout. To pull the required testing dependencies and verify the flaw locally, execute the following commands in order:

### 1. Clone the Repository
```bash
git clone https://github.com/fluffypill0w/tamaswap-dynamic-weth-architectural-flaw.git
cd tamaswap-dynamic-weth-architectural-flaw
```

### 2. Scaffold Environment & Fetch Dependencies
```bash
mkdir -p lib && forge install foundry-rs/forge-std Bacon-labs/tamaswap --no-git
```

### 3. Run the Live Fork Test Suite
Execute the block-sensitive simulation assertions against an active Ethereum Mainnet fork provider (e.g., LlamaRPC or Alchemy):
```bash
forge test -vv
```
