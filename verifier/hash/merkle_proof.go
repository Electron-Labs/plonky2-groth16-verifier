package hash

import (
	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	poseidon "github.com/Electron-Labs/plonky2-groth16-verifier/poseidon/goldilocks"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/types"
	"github.com/consensys/gnark/frontend"
)

func VerifyMerkleProofToCap(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	leaf_data []goldilocks.GoldilocksVariable,
	leaf_index_bits []frontend.Variable,
	merkle_cap types.MerkleCapVariable,
	proof types.MerkleProofVariable,
) {
	poseidon_goldilocks := &poseidon.PoseidonGoldilocks{}
	hasher := NewHasher(api, rangeChecker, poseidon_goldilocks)
	current_digest := hasher.HashOrNoop(leaf_data)
	for i, sibling_digest := range proof.Siblings {
		bit := leaf_index_bits[i]
		left := types.SelectHashOut(
			api,
			bit,
			sibling_digest,
			current_digest,
		)
		right := types.SelectHashOut(
			api,
			bit,
			current_digest,
			sibling_digest,
		)
		current_digest = hasher.TwoToOne(left, right)
	}
	var cap_hash types.HashOutVariable
	if len(merkle_cap) == 1 {
		cap_hash = merkle_cap[0]
	} else {
		cap_hash = types.SelectHashOutRecursive(api, leaf_index_bits[len(proof.Siblings):], merkle_cap)[0]
	}
	for i := 0; i < types.HASH_OUT; i++ {
		api.AssertIsEqual(current_digest.HashOut[i].Limb, cap_hash.HashOut[i].Limb)
	}
}
