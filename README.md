# crystal-caves-zk

## Overview

This repository contains a set of smart contracts that form the backbone of the Crystal Caves game. These contracts handle various aspects of the system, from the core functionalities to specific utilities and zero-knowledge proof integrations.

The primary smart contracts include:

- CrystalCavesBaseV3_1.sol: Core contract that handles the foundational logic of Crystal Caves.
- CrystalCavesZKV3_1.sol: Main contract implementing zero-knowledge proof functionality using zk-SNARKs.
- CrystalCavesZKHelperV3_1.sol: A helper contract responsible for verifying zero-knowledge (ZK) proofs in the system.

## Contracts
**1. CrystalCavesBaseV3_1.sol**
- Acts as the core backbone of the Crystal Caves game, managing basic logic and user interactions.
- Contains common variables and core functionalities for the game.
- Must be inherited by other contracts to utilize the full functionality.

**2. CrystalCavesZKV3_1.sol**
- Implements the full game mechanics while integrating ZK verification.
- Responsible for verifying proofs and ensuring that game interactions maintain user privacy.
- Relies on ZKHelper for proof verification to separate large logic blocks due to contract size limitations.

**3. CrystalCavesZKHelperV3_1.sol**
- Handles the verification of ZK proofs, separated for size optimization.
- Used by CrystalCavesZKV3_1.sol to verify proofs without exceeding the EVM contract size limit.
- Focuses on cryptographic computations, ensuring efficient proof validation.
