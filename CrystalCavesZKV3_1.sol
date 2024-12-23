// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./CrystalCavesBaseV3_1.sol";
import "./CrystalCavesZKHelperV3_1.sol";

// Struct for UnlockDepth function input
struct UnlockDepthInput {
    uint256[2] _a;
    uint256[2][2] _b;
    uint256[2] _c;
    uint256[6] _input; // userMiMCHash, globalMiMcHash, xMax, yMax, userHashKey, globalHashKey
}

struct MineBlockInputBatch {
    uint256[2][] _a;
    uint256[2][2][] _b;
    uint256[2][] _c;
    uint256[8][] _input; // userMiMCHash2, userMiMCHash1, globalMiMcHash2, globalMiMcHash1, xMax, yMax, userHashKey, globalHashKey
    BlockType[] blockType;
    uint256[] defogNonce;
    uint256[] mineNonce;
}

contract CrystalCavesZKV3_1 is CrystalCavesBaseV3_1 {
    // Helper address
    address public helperAddress;

    function setHelperAddress(
        address _helperAddress
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        helperAddress = _helperAddress;
    }

    // Initialize a new user in the game
    function initUserZK(
        UnlockDepthInput calldata initBlock,
        bytes calldata admissionSignature,
        uint256 admissionNonce
    ) external {
        // Call the base _initUser function
        _initUser(
            msg.sender,
            initBlock._input[1],
            0,
            admissionSignature,
            admissionNonce
        );

        // Check ZK for init block
        _checkInitZK(msg.sender, initBlock, 0);
    }

    // Mine multiple blocks for the user
    function mineBlocksOnlyZK(
        MineBlockInputBatch calldata blocksData
    ) external {
        // Call the base _mineBlocksOnly function
        uint256[] memory blockHashes = new uint256[](blocksData._a.length);
        uint256[] memory neighbourHashes = new uint256[](blocksData._a.length);
        for (uint256 i = 0; i < blocksData._a.length; i++) {
            blockHashes[i] = blocksData._input[i][3];
            neighbourHashes[i] = blocksData._input[i][2];
        }
        _mineBlocksOnly(
            msg.sender,
            blockHashes,
            neighbourHashes,
            blocksData.blockType,
            blocksData.defogNonce,
            blocksData.mineNonce
        );

        // Check ZK for mining blocks
        _checkMineBlocksZK(msg.sender, blocksData);
    }

    // Mine multiple blocks for the user and unlock the next depth
    function mineBlocksAndUnlockDepthZK(
        MineBlockInputBatch calldata blocksData,
        UnlockDepthInput calldata initBlock
    ) external {
        // Call the base _mineBlocksOnly function
        uint256[] memory blockHashes = new uint256[](
            blocksData.blockType.length
        );
        uint256[] memory neighbourHashes = new uint256[](
            blocksData.blockType.length
        );
        for (uint256 i = 0; i < blocksData.blockType.length; i++) {
            blockHashes[i] = blocksData._input[i][3];
            neighbourHashes[i] = blocksData._input[i][2];
        }
        // Call the base _mineBlocksAndUnlockDepth function
        _mineBlocksAndUnlockDepth(
            msg.sender,
            blockHashes,
            neighbourHashes,
            blocksData.blockType,
            blocksData.defogNonce,
            blocksData.mineNonce,
            userStateMap[msg.sender].currentDepth + 1,
            initBlock._input[1]
        );

        // Check ZK for mining blocks
        _checkMineBlocksZK(msg.sender, blocksData);

        // Check ZK for init block
        _checkInitZK(
            msg.sender,
            initBlock,
            userStateMap[msg.sender].currentDepth + 1
        );
    }

    // Helper function to unlock the depth for the user
    function _checkInitZK(
        address userAddress,
        UnlockDepthInput calldata initBlock,
        uint32 newDepth
    ) private view {
        if (
            !CrystalCavesZKHelperV3_1(helperAddress).verifyInitV2Proof(
                initBlock._a,
                initBlock._b,
                initBlock._c,
                initBlock._input
            )
        ) {
            revert("ZKFailed");
        }

        // Verify the ZK-SNARK flags and proof
        _snarkFlagsCheck(
            [
                initBlock._input[2],
                initBlock._input[3],
                initBlock._input[4],
                initBlock._input[5]
            ],
            userAddress,
            newDepth
        );
    }

    function _checkMineBlocksZK(
        address userAddress,
        MineBlockInputBatch calldata blocksData
    ) private view {
        // Make sure the ZK input is valid
        if (
            blocksData._a.length != blocksData._b.length ||
            blocksData._a.length != blocksData._c.length ||
            blocksData._a.length != blocksData._input.length ||
            blocksData._a.length != blocksData.blockType.length ||
            blocksData._a.length != blocksData.defogNonce.length ||
            blocksData._a.length != blocksData.mineNonce.length
        ) {
            revert("InvalidZKInputLength");
        }

        // Ensure the ZK batch proof is valid
        if (
            !CrystalCavesZKHelperV3_1(helperAddress).verifyMineV2ProofBatch(
                blocksData._a,
                blocksData._b,
                blocksData._c,
                blocksData._input
            )
        ) {
            revert("ZKFailed");
        }

        for (uint256 i = 0; i < blocksData._a.length; i++) {
            // Ensure the ZK-SNARK flags are valid
            _snarkFlagsCheck(
                [
                    blocksData._input[i][4],
                    blocksData._input[i][5],
                    blocksData._input[i][6],
                    blocksData._input[i][7]
                ],
                userAddress,
                userStateMap[userAddress].currentDepth
            );
        }
    }

    // Helper function to check if the ZK-SNARK flags are valid
    function _snarkFlagsCheck(
        uint256[4] memory flags,
        address userAddress,
        uint256 userDepth
    ) public view {
        if (
            !CrystalCavesZKHelperV3_1(helperAddress).verifyFlags(
                flags,
                userAddress,
                userDepth,
                gameState.hashKey,
                gameConfig.general.sizeX,
                gameConfig.general.sizeY
            )
        ) {
            revert("ZKFlagsFailed");
        }
    }
}
