// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;
import "../../Library/ZkVerifierV2.sol";
import "./CrystalCavesZKV3_1.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

struct BatchProof {
    Pairing.G1Point aggregatedA;
    Pairing.G1Point aggregatedC;
    Pairing.G1Point aggregated_vk_x;
    Pairing.G1Point[] P;
    Pairing.G2Point[] Q;
    uint256[] r;
    uint256 sumWeights;
}

uint256 constant snarkScalarField = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

contract CrystalCavesZKHelperV3_1 is ZkVerifier {
    struct VerifyParams {
        Proof[] proofs;
        uint256[][] inputs;
    }

    function verifyBatch(
        uint256[][] memory inputs,
        Proof[] memory proofs,
        VerifyingKey memory vk
    ) internal view returns (uint256) {
        uint256 batchSize = proofs.length;
        require(batchSize == inputs.length, "Batch size mismatch");
        require(vk.IC.length > 0, "Invalid verifying key");

        BatchProof memory bp;
        // Generate random scalars r_i
        bp.r = new uint256[](batchSize);
        uint256 seed = uint256(
            keccak256(
                abi.encodePacked(
                    block.timestamp,
                    block.prevrandao,
                    tx.origin,
                    proofs[0].A.X % 100000
                )
            )
        );
        for (uint256 i = 0; i < batchSize; i++) {
            bp.r[i] =
                (uint256(keccak256(abi.encodePacked(seed, i))) %
                    snarkScalarField) %
                1e18;
            if (bp.r[i] == 0) {
                bp.r[i] = 1;
            }
            bp.sumWeights += bp.r[i];
        }

        // Initialize aggregated points
        bp.aggregatedA = Pairing.G1Point(0, 0);
        bp.aggregatedC = Pairing.G1Point(0, 0);
        bp.aggregated_vk_x = Pairing.G1Point(0, 0);

        // Initialize pairing inputs
        uint256 totalPairings = batchSize + 3; // Each proof adds two pairings, plus two constants
        bp.P = new Pairing.G1Point[](totalPairings);
        bp.Q = new Pairing.G2Point[](totalPairings);

        uint256 count = 0;

        // Prepare pairing inputs for vk.alfa1 and vk.beta2
        bp.P[count] = Pairing.scalar_mul(vk.alfa1, bp.sumWeights);
        bp.Q[count] = vk.beta2;
        count++;

        // Prepare pairing inputs for vk.alfa2 and vk.beta1
        for (uint256 i = 0; i < batchSize; i++) {
            require(
                inputs[i].length + 1 == vk.IC.length,
                "Invalid input length"
            );

            // Aggregate vk_x points using random scalars
            Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
            for (uint256 j = 0; j < inputs[i].length; j++) {
                require(
                    inputs[i][j] < snarkScalarField,
                    "Input exceeds field size"
                );
                vk_x = Pairing.addition(
                    vk_x,
                    Pairing.scalar_mul(vk.IC[j + 1], inputs[i][j])
                );
            }
            vk_x = Pairing.addition(vk_x, vk.IC[0]);
            bp.aggregated_vk_x = Pairing.addition(
                bp.aggregated_vk_x,
                Pairing.scalar_mul(vk_x, bp.r[i])
            );

            // Aggregate A and C points using random scalars
            bp.aggregatedA = Pairing.addition(
                bp.aggregatedA,
                Pairing.scalar_mul(proofs[i].A, bp.r[i])
            );

            // Aggregate C points using random scalars
            bp.aggregatedC = Pairing.addition(
                bp.aggregatedC,
                Pairing.scalar_mul(proofs[i].C, bp.r[i])
            );

            // Prepare pairing inputs for each proof's A and B
            bp.P[count] = Pairing.negate(
                Pairing.scalar_mul(proofs[i].A, bp.r[i])
            );
            bp.Q[count] = proofs[i].B;
            count++;
        }

        // Prepare pairing input for aggregated A and vk.beta1
        bp.P[count] = bp.aggregated_vk_x;
        bp.Q[count] = vk.gamma2;
        count++;

        // Prepare pairing input for aggregated C and vk.delta2
        bp.P[count] = bp.aggregatedC;
        bp.Q[count] = vk.delta2;
        count++;

        // Perform the pairing check
        if (!Pairing.pairing(bp.P, bp.Q)) {
            return 1; // Verification failed
        }
        return 0; // Verification passed
    }

    // Modified verifyMineV2Proof to handle multiple proofs
    function verifyMineV2ProofBatch(
        uint256[2][] memory a,
        uint256[2][2][] calldata b,
        uint256[2][] calldata c,
        uint256[8][] calldata input
    ) public view returns (bool) {
        require(
            a.length == b.length &&
                b.length == c.length &&
                c.length == input.length,
            "Array lengths must match"
        );

        VerifyParams memory vp;

        // Convert calldata arrays to memory structs
        vp.proofs = new Proof[](a.length);
        vp.inputs = new uint256[][](a.length);

        for (uint256 i = 0; i < a.length; i++) {
            vp.proofs[i] = Proof({
                A: Pairing.G1Point(a[i][0], a[i][1]),
                B: Pairing.G2Point(
                    [b[i][0][0], b[i][0][1]],
                    [b[i][1][0], b[i][1][1]]
                ),
                C: Pairing.G1Point(c[i][0], c[i][1])
            });

            // Convert fixed array to dynamic array
            vp.inputs[i] = new uint256[](input[i].length);
            for (uint256 j = 0; j < input[i].length; j++) {
                vp.inputs[i][j] = input[i][j];
            }
        }

        VerifyingKey memory vk = MineV2VerifyingKey();
        if (verifyBatch(vp.inputs, vp.proofs, vk) == 0) {
            return true;
        } else {
            return false;
        }
    }

    // Helper function to check if the ZK-SNARK flags are valid
    function verifyFlags(
        uint256[4] calldata flags,
        address userAddress,
        uint256 userDepth,
        uint256 hashKey,
        uint16 sizeX,
        uint16 sizeY
    ) public pure returns (bool) {
        // Check if the flags are valid
        uint256 userHashKey = uint256(
            keccak256(abi.encodePacked(userAddress, hashKey, userDepth))
        );
        uint256 globalHashKey = uint256(
            keccak256(abi.encodePacked(hashKey, userDepth))
        );

        if (
            flags[0] != (sizeX) % snarkScalarField ||
            flags[1] != (sizeY) % snarkScalarField ||
            flags[2] != (userHashKey) % snarkScalarField ||
            flags[3] != (globalHashKey) % snarkScalarField
        ) {
            return false;
        } else {
            return true;
        }
    }
}
