// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

// Constants
uint32 constant REWARD_DIVIDEND = 100000; // Dividend for reward calculation
uint32 constant DEFOG_DIVIDEND = 100; // Dividend for defog probabilities
bytes32 constant MANAGER_ROLE = keccak256("MANAGER_ROLE"); // Operator role for the game
uint64 constant ONE_HOUR = 60 * 60; // One hour in seconds
uint64 constant ONE_DAY = 60 * 60 * 24; // One day in seconds

// Enum for the different types of blocks
enum BlockType {
    NULL, // Not a valid block type / Unknown
    DIRT, // No reward
    STONE, // No reward
    GOLD, // Final reward
    DIAMOND // Instant reward + Final reward
}

// Struct for general configuration
struct GeneralConfig {
    uint8 caveType; // Type of the cave (e.g. 0 for null, 1 for non-ZK, 2 for ZK)
    string name; // Name of the game site
    uint16 sizeX; // Size of the game map in the x direction per depth per user
    uint16 sizeY; // Size of the game map in the y direction per depth per user
    uint32 maxEnergy; // Maximum energy for each user
    uint64 energyResetTime; // Energy recover interval in seconds
    uint64 startTime; // Start time of the game in seconds since epoch
    uint64 gameDuration; // Duration of the total game in seconds (e.g. 60 * 60 * 24 * 5 = 5 days)
    address trustedSigner; // Address of the trusted signer for admitting users
}

// Struct for defog configuration
struct DefogConfig {
    uint32 maxRounds; // Number of defog rounds
    uint32 repeatRounds; // Number of repeated results needed to defog a block
    uint32[3] thresholds; // Thresholds for defog probabilities
}

// Struct for mining configuration
struct MiningConfig {
    uint8[4] blockDifficulties; // PoW base difficulties for each block type
    uint16[4] blockMiningTimes; // Target mining times for each block type in seconds (For Dynamic PoW difficulty)
}

// Struct for reward configuration
struct RewardConfig {
    address tokenAddress; // Address of the reward token
    uint256 dailyTotalMaxReward; // Maximum reward for each day
    uint256 dailyUserMaxReward; // Maximum reward for each day for each user
    uint256 hourlyTotalMaxReward; // Maximum reward for each hour
    uint256 userMaxReward; // Maximum total reward for each user
    RewardLevel[4] blockReward; // Reward for each block type
}

// Struct for block reward configuration
struct RewardLevel {
    uint32 possibility;
    uint256 minAmount;
    uint256 maxAmount;
}

// Struct for game configuration (needed by constructor)
struct GameConfig {
    // Seperate struct for each configuration
    GeneralConfig general;
    DefogConfig defog;
    MiningConfig mining;
    RewardConfig reward;
}

// Struct for current game state (initialized by constructor)
struct GameState {
    uint32 userCount; // Current number of inited users in the game
    uint32 totalMinedBlockCount; // Total number of mined blocks
    uint32[4] totalMinedBlockTypeCounts; // Total number of mined blocks by all users for each type
    uint256 hashKey; // Site hash key for determining block types
    // Reward Pool State
    uint64 currentDay; // Current day for the game reward
    uint64 currentHour; // Current hour for the game reward
    uint256 currentDayTotalReward; // Current reward given for the day
    uint256 currentHourTotalReward; // Current reward given for the hour
    uint256 totalReward; // Total amount of deposited reward in the pool by the managers
    uint256 remainingReward; // Remaining amount of balance in the reward pool
    uint256 totalPending; // Total amount of reward pending to be claimed by users
    uint256 totalClaimed; // Total amount of reward claimed by users
}

// Struct for user-specific game statistics
struct UserState {
    uint64 initTime; // Timestamp when the user initialized
    uint32 difficulty; // PoW difficulty offset for the user (use with blockTypeDifficulties)
    uint32 currentDepth; // Current round index for the user
    uint32 currentDepthMinedBlockCount; // Number of blocks mined by the user in the current depth
    uint256 currentDepthInitBlockHash; // Hash of the initial block for the current depth
    uint32 remainingEnergy; // Remaining energy for the user in the current energy reset round
    uint32[4] minedBlockTypeCounts; // Number of blocks mined by the user for each type in total
    uint64 lastMineTime; // Last timestamp when the user mined
    uint256 powSeed; // PoW seed for the user
    // Reward State
    uint256 earnedReward; // Total amount of reward earned by the user
    uint256 currentBalance; // Token balance for the user
    uint256 claimedReward; // Total amount of reward claimed by the user
    uint64 lastEarnedDay; // Last day when the user earned reward
    uint256 currentDayEarnedReward; // Total amount of reward earned by the user for the current day
}

contract CrystalCavesBaseV3_1 is
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable
{
    // Global game information
    bool public bypassPoW; // Bypass PoW for testing
    GameConfig public gameConfig;
    GameState public gameState;

    // User-specific game information maps
    mapping(address => UserState) public userStateMap; // User address => user state

    // Block information maps
    mapping(address => mapping(uint256 => bool)) public blockMinedMap; // User address => block global hash => mined

    // Events
    event UserInited(address userAddress, uint256 initTime);
    event BlockMined(
        address userAddress,
        uint256 blockHash,
        BlockType blockType,
        uint256 userDepth,
        address tokenAddress,
        uint256 tokenAmount
    );
    event DepthUnlocked(
        address userAddress,
        uint256 blockHash,
        uint256 userDepth,
        uint256 unlockTime
    );
    event DifficultyUpdated(address userAddress, uint32 newDifficulty);
    event RewardClaimed(
        address userAddress,
        address tokenAddress,
        uint256 tokenAmount
    );

    function initialize(
        address _owner,
        GameConfig memory _gameConfig
    ) public initializer {
        // Initialize inherited contracts
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();

        // Initialize the AccessControl roles
        _grantRole(DEFAULT_ADMIN_ROLE, _owner);
        _grantRole(MANAGER_ROLE, _owner);

        // Initialize the game configuration
        gameConfig = _gameConfig; // Set the game configuration

        // Initialize the game state
        gameState.hashKey = uint256(
            keccak256(
                abi.encodePacked("hashKey", block.timestamp, block.number)
            )
        );
    }

    // Override the supportsInterface function
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(AccessControlUpgradeable) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    // Allow the owner to update the game configuration
    function updateGameConfig(
        GameConfig memory _gameConfig
    ) public onlyRole(MANAGER_ROLE) {
        gameConfig = _gameConfig;
    }

    // Allow the owner to pause/unpause the game
    function setGamePaused(bool _paused) public onlyRole(MANAGER_ROLE) {
        if (_paused) {
            _pause(); // Pause the game
        } else {
            _unpause(); // Unpause the game
        }
    }

    // Allow the owner to update the bypassPoW flag
    function setBypassPoW(bool _bypassPoW) public onlyRole(MANAGER_ROLE) {
        bypassPoW = _bypassPoW;
    }

    // Allow the owner to deposit tokens to the reward pool
    function depositToRewardPool(
        uint256 _amount
    ) public onlyRole(MANAGER_ROLE) {
        // Transfer the tokens from the sender to the contract
        IERC20(gameConfig.reward.tokenAddress).transferFrom(
            msg.sender,
            address(this),
            _amount
        );

        // Update the pool balance
        gameState.totalReward += _amount;
        gameState.remainingReward += _amount;
    }

    // Allow the owner to withdraw tokens from the reward pool
    function withdrawFromRewardPool(
        uint256 _amount
    ) public onlyRole(MANAGER_ROLE) {
        // Ensure the pool has enough balance
        if (gameState.remainingReward < _amount) {
            revert("NoBalance");
        }

        // Transfer the tokens from the contract to the sender
        IERC20(gameConfig.reward.tokenAddress).transfer(msg.sender, _amount);

        // Update the pool balance
        gameState.remainingReward -= _amount;
        gameState.totalClaimed += _amount;
    }

    // Allow the owner to withdraw tokens from the contract in case of emergency
    function emergencyWithdraw(
        uint256 _amount
    ) public onlyRole(MANAGER_ROLE) nonReentrant {
        // Transfer the tokens from the contract to the sender
        IERC20(gameConfig.reward.tokenAddress).transfer(msg.sender, _amount);
    }

    // Allow users to claim their tokens from the reward pool
    function claimReward() public nonReentrant {
        // Check if all the global stats are valid
        if (
            IERC20(gameConfig.reward.tokenAddress).balanceOf(address(this)) <
            gameState.remainingReward + gameState.totalPending ||
            gameState.totalReward !=
            gameState.remainingReward +
                gameState.totalPending +
                gameState.totalClaimed
        ) {
            revert("GameError");
        }

        // Check if all the user stats are valid
        if (
            userStateMap[msg.sender].currentBalance !=
            userStateMap[msg.sender].earnedReward -
                userStateMap[msg.sender].claimedReward
        ) {
            revert("UserError");
        }

        // Transfer the tokens from the contract to the sender
        IERC20(gameConfig.reward.tokenAddress).transfer(
            msg.sender,
            userStateMap[msg.sender].currentBalance
        );

        // Emit the RewardClaimed event
        emit RewardClaimed(
            msg.sender,
            gameConfig.reward.tokenAddress,
            userStateMap[msg.sender].currentBalance
        );

        // Update the user's token balance
        gameState.totalPending -= userStateMap[msg.sender].currentBalance;
        gameState.totalClaimed += userStateMap[msg.sender].currentBalance;
        userStateMap[msg.sender].claimedReward += userStateMap[msg.sender]
            .currentBalance;
        userStateMap[msg.sender].currentBalance = 0;
    }

    // Helper function to initialize a user in the game
    function _initUser(
        address userAddress,
        uint256 blockHash,
        uint32 nextDepth,
        bytes memory admissionSignature,
        uint256 admissionNonce
    ) internal {
        // Check if the game has ended and the user isn't initialized
        _initCheck(userAddress);

        // Ensure the signature is valid to admit the user
        signatureCheck(userAddress, admissionNonce, admissionSignature);

        // Mine the first block for the user
        _safeInit(userAddress);

        // Take the user to the next round
        _unlockDepth(userAddress, blockHash, nextDepth);
    }

    // Helper function to unlock the depth for the user
    function _unlockDepth(
        address userAddress,
        uint256 blockHash,
        uint32 newDepth
    ) internal {
        // Ensure the init block is not already mined
        if (blockMinedMap[userAddress][blockHash]) {
            revert("BlockAlreadyMined");
        }

        // Take the user to the next round
        _safeUnlockDepth(userAddress, newDepth, blockHash);
    }

    // Helper function to mine multiple blocks for the user
    function _mineBlocks(
        address userAddress,
        uint256[] memory blockHashes,
        uint256[] memory neighbourHashes,
        BlockType[] memory blockTypes,
        uint256[] memory defogNonces,
        uint256[] memory mineNonces
    ) internal {
        // Mine the blocks for the user
        uint32[4] memory blockTypeCounts = [(uint32)(0), 0, 0, 0];
        for (uint256 i = 0; i < blockHashes.length; i++) {
            // Count the block types
            blockTypeCounts[uint256(blockTypes[i]) - 1] += 1;

            // Mine the block for the user
            _mineBlock(
                userAddress,
                blockHashes[i],
                neighbourHashes[i],
                blockTypes[i],
                defogNonces[i],
                mineNonces[i]
            );
        }

        // Update the game after mining
        _safeMineBlocksUpdate(
            userAddress,
            blockTypeCounts,
            (uint32)(blockHashes.length),
            blockHashes[blockHashes.length - 1]
        );
    }

    // Helper function for mining a block
    function _mineBlock(
        address userAddress,
        uint256 blockHash,
        uint256 neighbourHash,
        BlockType blockType,
        uint256 defogNonce,
        uint256 mineNonce
    ) internal {
        // Ensure the block type is valid
        if (
            uint256(blockType) < uint256(BlockType.DIRT) ||
            uint256(blockType) > uint256(BlockType.DIAMOND)
        ) {
            revert("InvalidBlockType");
        }

        // Ensure the neighbour block is accessible
        if (!blockMinedMap[userAddress][neighbourHash]) {
            revert("NeighbourNotMined");
        }

        // Ensure this block is not already mined
        if (blockMinedMap[userAddress][blockHash]) {
            revert("BlockAlreadyMined");
        }

        // Ensure the defog proof is valid
        _defogCheck(blockHash, defogNonce, blockType);

        // Ensure the PoW proof is valid
        if (!bypassPoW) {
            _PoWCheck(
                userStateMap[msg.sender].powSeed,
                blockHash,
                mineNonce,
                getBlockDifficulty(blockType, msg.sender)
            );
        }

        // Mine the block for the user
        _safeMineBlock(userAddress, blockHash, blockType);
    }

    // Helper function to mine multiple blocks only for the user without unlocking the next depth
    function _mineBlocksOnly(
        address userAddress,
        uint256[] memory blockHashes,
        uint256[] memory neighbourHashes,
        BlockType[] memory blockTypes,
        uint256[] memory defogNonces,
        uint256[] memory mineNonces
    ) internal {
        // Check if the game has ended and the user is initialized
        _mineCheck(userAddress);

        // Ensure the user shouldn't unlock the next depth
        if (shouldUnlockDepth(userAddress, blockHashes.length)) {
            revert("MustUnlockDepth");
        }

        // Mine the blocks for the user
        _mineBlocks(
            userAddress,
            blockHashes,
            neighbourHashes,
            blockTypes,
            defogNonces,
            mineNonces
        );
    }

    // Helper function to mine multiple blocks for the user and unlock the next depth
    function _mineBlocksAndUnlockDepth(
        address userAddress,
        uint256[] memory blockHashes,
        uint256[] memory neighbourHashes,
        BlockType[] memory blockTypes,
        uint256[] memory defogNonces,
        uint256[] memory mineNonces,
        uint32 nextDepth,
        uint256 unlockBlockHash
    ) internal {
        // Check if the game has ended and the user is initialized
        _mineCheck(userAddress);

        // Ensure the user should unlock the next depth
        if (!shouldUnlockDepth(userAddress, blockHashes.length)) {
            revert("CannotUnlockDepth");
        }

        // Mine the blocks for the user
        _mineBlocks(
            userAddress,
            blockHashes,
            neighbourHashes,
            blockTypes,
            defogNonces,
            mineNonces
        );

        // Unlock the next depth for the user
        _unlockDepth(userAddress, unlockBlockHash, nextDepth);
    }

    // Get the user's block type counts
    function getUserBlockTypeCounts(
        address userAddress
    ) public view returns (uint32[4] memory blockTypeCounts) {
        return userStateMap[userAddress].minedBlockTypeCounts;
    }

    // Get the user's remaining energy
    function getUserRemainingEnergy(
        address userAddress
    ) public view returns (uint32 remainingEnergy) {
        // If the user is not initialized, return the max energy
        if (userStateMap[userAddress].initTime == 0) {
            return gameConfig.general.maxEnergy;
        }

        uint256 lastMineRound = (userStateMap[userAddress].lastMineTime -
            gameConfig.general.startTime) / gameConfig.general.energyResetTime;

        uint256 currentRound = (block.timestamp -
            gameConfig.general.startTime) / gameConfig.general.energyResetTime;

        if (currentRound > lastMineRound) {
            return gameConfig.general.maxEnergy;
        } else {
            return userStateMap[userAddress].remainingEnergy;
        }
    }

    // Helper function to get if the game has ended
    // The game is ended if:
    // 1. it's paused
    // 2. the game duration has passed
    // 3. it's not start time yet
    function getGameEnded() public view returns (bool ended) {
        return (paused() ||
            block.timestamp >
            gameConfig.general.startTime + gameConfig.general.gameDuration ||
            block.timestamp < gameConfig.general.startTime);
    }

    // Helper function to get the current game day
    function getCurrentRewardDay() public view returns (uint64) {
        return
            (uint64(block.timestamp) - gameConfig.general.startTime) / ONE_DAY;
    }

    // Helper function to get the current game hour
    function getCurrentRewardHour() public view returns (uint64) {
        return
            (uint64(block.timestamp) - gameConfig.general.startTime) / ONE_HOUR;
    }

    // Helper function to get if multiple blocks are mined
    function getBlocksMined(
        address userAddress,
        uint256[] memory globalBlockHashes
    ) public view returns (bool[] memory) {
        // Iterate over the block coordinates and get if the blocks are mined
        bool[] memory mined = new bool[](globalBlockHashes.length);
        for (uint256 i = 0; i < globalBlockHashes.length; i++) {
            mined[i] = blockMinedMap[userAddress][globalBlockHashes[i]];
        }
        return mined;
    }

    // Helper function to get the block info for mining
    function getBlockMineConfig(
        address userAddress,
        uint256 globalBlockHash,
        BlockType blockType
    ) public view returns (bool mined, uint256 powSeed, uint256 difficulty) {
        // Get if the block is already mined
        mined = blockMinedMap[userAddress][globalBlockHash];

        // Get the PoW seed for the user
        powSeed = userStateMap[userAddress].powSeed;

        // Get the block difficulty
        difficulty = getBlockDifficulty(blockType, userAddress);

        return (mined, powSeed, difficulty);
    }

    // Helper function to determine user's dynamic PoW difficulty
    function getBlockDifficulty(
        BlockType blockType,
        address userAddress
    ) public view returns (uint256) {
        if (blockType == BlockType.NULL) {
            return 0;
        }

        return
            gameConfig.mining.blockDifficulties[uint256(blockType) - 1] +
            userStateMap[userAddress].difficulty;
    }

    // Helper function to check if the user should go to the next depth
    function shouldUnlockDepth(
        address userAddress,
        uint256 newBlocksCount
    ) public view returns (bool) {
        return (userStateMap[userAddress].currentDepthMinedBlockCount +
            newBlocksCount >=
            (gameConfig.general.sizeX * gameConfig.general.sizeY));
    }

    // Helper function to ensure the user's signature is trusted
    function signatureCheck(
        address userAddress,
        uint256 nonce,
        bytes memory signature
    ) public view {
        // Recover the signer from the signature
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encode(address(this), userAddress, nonce))
            )
        );

        // Ensure the signer is the trusted signer
        if (
            ECDSA.recover(messageHash, signature) !=
            gameConfig.general.trustedSigner
        ) {
            revert("InvalidSignature");
        }
    }

    // Get important game information for the frontend
    function getGameInfo()
        public
        view
        returns (
            uint8 caveType,
            string memory name,
            uint16 sizeX,
            uint16 sizeY,
            uint64 gameDuration,
            uint64 startTime,
            uint64 energyResetTime,
            uint32 maxEnergy,
            uint32 userCount,
            uint32 totalMinedBlockCount,
            uint256 hashKey
        )
    {
        return (
            gameConfig.general.caveType,
            gameConfig.general.name,
            gameConfig.general.sizeX,
            gameConfig.general.sizeY,
            gameConfig.general.gameDuration,
            gameConfig.general.startTime,
            gameConfig.general.energyResetTime,
            gameConfig.general.maxEnergy,
            gameState.userCount,
            gameState.totalMinedBlockCount,
            gameState.hashKey
        );
    }

    // Get all the game information
    function getAllGameInfo()
        public
        view
        returns (
            GeneralConfig memory general,
            DefogConfig memory defog,
            MiningConfig memory mining,
            RewardConfig memory reward,
            GameState memory state
        )
    {
        return (
            gameConfig.general,
            gameConfig.defog,
            gameConfig.mining,
            gameConfig.reward,
            gameState
        );
    }

    // Helper function to grant the reward for mining a block
    function _grantReward(
        address userAddress,
        uint256 blockUserHash,
        BlockType blockType
    ) internal returns (uint256 rewardAmount) {
        // Update current day and hour reward if needed
        uint64 currentDay = getCurrentRewardDay();
        if (currentDay > gameState.currentDay) {
            gameState.currentDay = currentDay;
            gameState.currentDayTotalReward = 0;
        }
        uint64 currentHour = getCurrentRewardHour();
        if (currentHour > gameState.currentHour) {
            gameState.currentHour = currentHour;
            gameState.currentHourTotalReward = 0;
        }

        if (currentDay > userStateMap[userAddress].lastEarnedDay) {
            userStateMap[userAddress].lastEarnedDay = currentDay;
            userStateMap[userAddress].currentDayEarnedReward = 0;
        }

        // Generate a random number for the reward
        uint256 randomNumber = uint256(
            keccak256(
                abi.encodePacked(
                    block.timestamp,
                    block.number,
                    blockUserHash,
                    userAddress
                )
            )
        );

        // Calculate the reward amount based on the block type
        RewardLevel memory rewardLevel = gameConfig.reward.blockReward[
            uint256(blockType) - 1
        ];

        if (randomNumber % REWARD_DIVIDEND < rewardLevel.possibility) {
            rewardAmount =
                rewardLevel.minAmount +
                (randomNumber %
                    (rewardLevel.maxAmount - rewardLevel.minAmount));
        }

        // Calculate the maximum reward amount for the user
        uint256 maxTotalRewardAmount = gameState.remainingReward;

        uint256 maxDailyRewardAmount = gameConfig.reward.dailyTotalMaxReward >
            gameState.currentDayTotalReward
            ? gameConfig.reward.dailyTotalMaxReward -
                gameState.currentDayTotalReward
            : 0;

        uint256 maxHourlyRewardAmount = gameConfig.reward.hourlyTotalMaxReward >
            gameState.currentHourTotalReward
            ? gameConfig.reward.hourlyTotalMaxReward -
                gameState.currentHourTotalReward
            : 0;

        uint256 maxUserDailyRewardAmount = gameConfig
            .reward
            .dailyUserMaxReward >
            userStateMap[userAddress].currentDayEarnedReward
            ? gameConfig.reward.dailyUserMaxReward -
                userStateMap[userAddress].currentDayEarnedReward
            : 0;

        uint256 maxUserRewardAmount = gameConfig.reward.userMaxReward >
            userStateMap[userAddress].earnedReward
            ? gameConfig.reward.userMaxReward -
                userStateMap[userAddress].earnedReward
            : 0;

        // Ensure the reward amount is the minimum of the above
        if (rewardAmount > maxTotalRewardAmount) {
            rewardAmount = maxTotalRewardAmount;
        }

        if (rewardAmount > maxDailyRewardAmount) {
            rewardAmount = maxDailyRewardAmount;
        }

        if (rewardAmount > maxUserDailyRewardAmount) {
            rewardAmount = maxUserDailyRewardAmount;
        }

        if (rewardAmount > maxHourlyRewardAmount) {
            rewardAmount = maxHourlyRewardAmount;
        }

        if (rewardAmount > maxUserRewardAmount) {
            rewardAmount = maxUserRewardAmount;
        }

        // Update the user's token balance
        userStateMap[userAddress].currentBalance += rewardAmount;
        userStateMap[userAddress].earnedReward += rewardAmount;
        userStateMap[userAddress].currentDayEarnedReward += rewardAmount;
        gameState.currentDayTotalReward += rewardAmount;
        gameState.currentHourTotalReward += rewardAmount;
        gameState.totalPending += rewardAmount;
        gameState.remainingReward -= rewardAmount;

        return rewardAmount;
    }

    // Helper function to update user's last mine time
    function _updateUserLastMineTime(address userAddress) internal {
        userStateMap[userAddress].lastMineTime = uint64(block.timestamp);
    }

    // Helper function to update user's remaining energy
    function _updateUserEnergy(address userAddress) internal {
        userStateMap[userAddress].remainingEnergy = getUserRemainingEnergy(
            userAddress
        );
    }

    // Helper function to use user's energy
    function _useUserEnergy(address userAddress, uint32 energyToUse) internal {
        if (userStateMap[userAddress].remainingEnergy < energyToUse) {
            revert("NotEnoughEnergy");
        } else {
            userStateMap[userAddress].remainingEnergy -= energyToUse;
        }
    }

    // Helper function to update user's difficulty
    function _updateUserDifficulty(
        address userAddress,
        uint64 targetTime
    ) internal {
        uint64 timeSinceLastMined = uint64(block.timestamp) -
            userStateMap[userAddress].lastMineTime;
        if (timeSinceLastMined < targetTime) {
            userStateMap[userAddress].difficulty += 1;
            emit DifficultyUpdated(
                userAddress,
                userStateMap[userAddress].difficulty
            );
        } else if (timeSinceLastMined > targetTime) {
            if (userStateMap[userAddress].difficulty > 0) {
                userStateMap[userAddress].difficulty -= 1;
                emit DifficultyUpdated(
                    userAddress,
                    userStateMap[userAddress].difficulty
                );
            }
        }
    }

    // Helper function to update user's PoW seed
    function _updateUserPoWSeed(
        address userAddress,
        uint256 lastGlobalBlockHash
    ) internal {
        userStateMap[userAddress].powSeed = uint256(
            keccak256(
                abi.encodePacked(
                    lastGlobalBlockHash,
                    userAddress,
                    block.timestamp,
                    block.prevrandao,
                    userStateMap[userAddress].powSeed
                )
            )
        );
    }

    // Helper function to safely initialize a user
    function _safeInit(address userAddress) internal {
        // Set the user state after initialization
        _updateUserLastMineTime(userAddress);
        _updateUserEnergy(userAddress);
        userStateMap[userAddress].initTime = uint64(block.timestamp);

        // Update global game state after initialization
        gameState.userCount += 1;

        // Emit the UserInited event
        emit UserInited(userAddress, block.timestamp);
    }

    // Helper function to take users to a new depth
    function _safeUnlockDepth(
        address userAddress,
        uint32 newDepth,
        uint256 globalBlockHash
    ) internal {
        // Mark the initial block as mined
        blockMinedMap[userAddress][globalBlockHash] = true;

        // Update the user depth stats after unlocking the next depth
        userStateMap[userAddress].currentDepth = newDepth;
        userStateMap[userAddress].currentDepthMinedBlockCount = 1;
        userStateMap[userAddress].currentDepthInitBlockHash = globalBlockHash;

        // Update the user's pow seed
        _updateUserPoWSeed(userAddress, globalBlockHash);

        // Emit the UserRoundStarted event
        emit DepthUnlocked(
            userAddress,
            globalBlockHash,
            newDepth,
            block.timestamp
        );
    }

    // Helper function to safely mine a block
    function _safeMineBlock(
        address userAddress,
        uint256 globalBlockHash,
        BlockType blockType
    ) internal {
        // Mark the block as mined
        blockMinedMap[userAddress][globalBlockHash] = true;

        // Update the user's token balance
        uint256 rewardAmount = _grantReward(
            userAddress,
            globalBlockHash,
            blockType
        );

        // Emit the BlockMined event
        emit BlockMined(
            userAddress,
            globalBlockHash,
            blockType,
            userStateMap[userAddress].currentDepth,
            rewardAmount > 0 ? gameConfig.reward.tokenAddress : address(0),
            rewardAmount
        );
    }

    // Helper function to update game after mining
    function _safeMineBlocksUpdate(
        address userAddress,
        uint32[4] memory blockTypeCounts,
        uint32 totalBlockCount,
        uint256 lastBlockGlobalHash
    ) internal {
        // Update all the counts
        uint64 targetTime = 0;

        for (uint32 i = 0; i < blockTypeCounts.length; i++) {
            // Update the global and user block type counts
            userStateMap[userAddress].minedBlockTypeCounts[
                i
            ] += blockTypeCounts[i];
            gameState.totalMinedBlockTypeCounts[i] += blockTypeCounts[i];
            targetTime +=
                gameConfig.mining.blockMiningTimes[i] *
                blockTypeCounts[i];
        }

        // Update the total mined block count
        userStateMap[userAddress]
            .currentDepthMinedBlockCount += totalBlockCount;
        gameState.totalMinedBlockCount += totalBlockCount;

        // Update the user remaining energy
        _updateUserEnergy(userAddress);
        _useUserEnergy(userAddress, totalBlockCount);

        // Update the user difficulty
        _updateUserDifficulty(userAddress, targetTime);

        // Update the last mine time
        _updateUserLastMineTime(userAddress);

        // Update the PoW seed
        _updateUserPoWSeed(userAddress, lastBlockGlobalHash);
    }

    // Helper function to check if the game has ended and the user isn't initialized
    function _initCheck(address userAddress) internal view {
        // Ensure the game hasn't ended
        if (getGameEnded()) {
            revert("GameAlreadyEnded");
        }

        // Ensure the user hasn't been initialized
        if (userStateMap[userAddress].initTime != 0) {
            revert("UserAlreadyInited");
        }
    }

    // Helper function to check if the game has ended and the user is initialized
    function _mineCheck(address userAddress) internal view {
        // Ensure the game hasn't ended
        if (getGameEnded()) {
            revert("GameAlreadyEnded");
        }

        // Ensure the user has been initialized
        if (userStateMap[userAddress].initTime == 0) {
            revert("UserNotInited");
        }
    }

    // Helper function to verify user's defog proof
    function _defogCheck(
        uint256 blockHash,
        uint256 nonce,
        BlockType blockType
    ) internal view {
        // If nonce is 0, no need to verify
        if (nonce == 0 && blockType == BlockType.DIRT) {
            return;
        }

        // Make sure nonce is valid
        if (
            nonce >= gameConfig.defog.maxRounds - gameConfig.defog.repeatRounds
        ) {
            revert("DefogFailed");
        }

        // Calculate defog thresholds
        uint256 lowerThreshold = (blockType == BlockType.DIRT)
            ? 0
            : gameConfig.defog.thresholds[uint256(blockType) - 2] /
                DEFOG_DIVIDEND;

        uint256 upperThreshold = (blockType == BlockType.DIAMOND)
            ? gameConfig.defog.maxRounds - 1
            : gameConfig.defog.thresholds[uint256(blockType) - 1] /
                DEFOG_DIVIDEND -
                1;

        for (uint256 i = 0; i < gameConfig.defog.repeatRounds; i++) {
            uint256 hash = uint256(
                keccak256(
                    abi.encodePacked(blockHash, gameState.hashKey, nonce + i)
                )
            );
            uint256 hashMod = hash % gameConfig.defog.maxRounds;
            if (hashMod < lowerThreshold || hashMod > upperThreshold) {
                revert("DefogFailed");
            }
        }
    }

    // Helper function to make sure PoW is valid (The first n bits should be 0)
    function _PoWCheck(
        uint256 seed,
        uint256 globalBlockHash,
        uint256 nonce,
        uint256 difficulty
    ) internal pure {
        uint256 hash = uint256(
            keccak256(abi.encodePacked(seed, globalBlockHash, nonce))
        );
        uint256 mask = (1 << difficulty) - 1;
        if ((hash & mask) != 0) {
            revert("PoWFailed");
        }
    }

    // Upgrade the contract
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    // Contract Version
    function version() public pure returns (string memory) {
        return "3.1.0";
    }

    // Cave Type
    function getCaveType() public view returns (uint256) {
        return gameConfig.general.caveType;
    }
}
