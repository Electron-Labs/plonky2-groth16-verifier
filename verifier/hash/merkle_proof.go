package hash

import (
	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	poseidonBn254 "github.com/Electron-Labs/plonky2-groth16-verifier/poseidon/bn254"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/types"
	"github.com/consensys/gnark/frontend"
)

func VerifyMerkleProofToCap(
	api frontend.API,
	leaf_data []goldilocks.GoldilocksVariable,
	leaf_index_bits []frontend.Variable,
	merkle_cap types.MerkleCapVariable,
	proof types.MerkleProofVariable,
) {
	poseidonBn254 := &poseidonBn254.PoseidonBn254{}
	hasher := NewPoseidonBn254Hasher(api, poseidonBn254)
	current_digest := hasher.HashOrNoop(api, leaf_data)
	for i, sibling_digest := range proof.Siblings {
		bit := leaf_index_bits[i]
		left := types.SelectPoseidonBn254HashOut(
			api,
			bit,
			sibling_digest,
			current_digest,
		)
		right := types.SelectPoseidonBn254HashOut(
			api,
			bit,
			current_digest,
			sibling_digest,
		)
		current_digest = hasher.TwoToOne(api, left, right)
	}
	var cap_hash types.PoseidonBn254HashOut
	if len(merkle_cap) == 1 {
		cap_hash = merkle_cap[0]
	} else {
		cap_hash = types.SelectPoseidonBn254HashOutRecursive(api, leaf_index_bits[len(proof.Siblings):], merkle_cap)[0]
	}
	api.AssertIsEqual(current_digest.HashOut, cap_hash.HashOut)
}
