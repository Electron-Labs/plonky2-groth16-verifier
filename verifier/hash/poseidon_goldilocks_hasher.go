package hash

import (
	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	poseidonGoldilocks "github.com/Electron-Labs/plonky2-groth16-verifier/poseidon/goldilocks"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/types"
	"github.com/consensys/gnark/frontend"
)

type PoseidonGoldilocksHasher struct {
	api          frontend.API
	rangeChecker frontend.Rangechecker
	poseidon     poseidonGoldilocks.Poseidon
}

func NewPoseidonGoldilocksHasher(api frontend.API, rangeChecker frontend.Rangechecker, poseidon poseidonGoldilocks.Poseidon) PoseidonGoldilocksHasher {
	return PoseidonGoldilocksHasher{
		api:          api,
		rangeChecker: rangeChecker,
		poseidon:     poseidon,
	}
}

func (hasher *PoseidonGoldilocksHasher) HashNoPad(inputs []goldilocks.GoldilocksVariable) types.PoseidonGoldilocksHashOut {
	permutation := poseidonGoldilocks.NewPermutation(hasher.api, hasher.rangeChecker, hasher.poseidon)

	numInputs := len(inputs)
	numChunks := (numInputs-1)/poseidonGoldilocks.SPONGE_RATE + 1
	for i := 0; i < numChunks; i++ {
		start := i * poseidonGoldilocks.SPONGE_RATE
		end := min((i+1)*poseidonGoldilocks.SPONGE_RATE, numInputs)
		permutation.Set(inputs[start:end])
		permutation.Permute()
	}

	var hash types.PoseidonGoldilocksHashOut
	hash.HashOut = make([]goldilocks.GoldilocksVariable, types.POSEIDON_GOLDILOCKS_HASH_OUT)
	for i, v := range permutation.Squeeze() {
		if i >= types.POSEIDON_GOLDILOCKS_HASH_OUT {
			break
		}
		hash.HashOut[i] = v
	}

	return hash
}

func (hasher *PoseidonGoldilocksHasher) HashOrNoop(inputs []goldilocks.GoldilocksVariable) types.PoseidonGoldilocksHashOut {
	var hash types.PoseidonGoldilocksHashOut
	hash.HashOut = make([]goldilocks.GoldilocksVariable, types.POSEIDON_GOLDILOCKS_HASH_OUT)
	if len(inputs) <= types.POSEIDON_GOLDILOCKS_HASH_OUT {
		for i := 0; i < types.POSEIDON_GOLDILOCKS_HASH_OUT; i++ {
			if i < len(inputs) {
				hash.HashOut[i] = inputs[i]

			} else {
				hash.HashOut[i] = goldilocks.GetGoldilocksVariable(0)
			}
		}
	} else {
		hash = hasher.HashNoPad(inputs)
	}
	return hash
}

func (hasher *PoseidonGoldilocksHasher) TwoToOne(left types.PoseidonGoldilocksHashOut, right types.PoseidonGoldilocksHashOut) types.PoseidonGoldilocksHashOut {
	return hasher.HashNoPad(append(left.HashOut, right.HashOut...))
}
