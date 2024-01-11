package hash

import (
	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	poseidon "github.com/Electron-Labs/plonky2-groth16-verifier/poseidon/goldilocks"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/types"
	"github.com/consensys/gnark/frontend"
)

type SpongeHasher struct {
	api          frontend.API
	rangeChecker frontend.Rangechecker
	poseidon     poseidon.Poseidon
}

func NewHasher(api frontend.API, rangeChecker frontend.Rangechecker, poseidon poseidon.Poseidon) SpongeHasher {
	return SpongeHasher{
		api:          api,
		rangeChecker: rangeChecker,
		poseidon:     poseidon,
	}
}

func (hasher *SpongeHasher) HashNoPad(inputs []goldilocks.GoldilocksVariable) types.HashOutVariable {
	permutation := poseidon.NewPermutation(hasher.api, hasher.rangeChecker, hasher.poseidon)

	numInputs := len(inputs)
	numChunks := (numInputs-1)/poseidon.SPONGE_RATE + 1
	for i := 0; i < numChunks; i++ {
		start := i * poseidon.SPONGE_RATE
		end := min((i+1)*poseidon.SPONGE_RATE, numInputs)
		permutation.Set(inputs[start:end])
		permutation.Permute()
	}

	var hash types.HashOutVariable
	hash.HashOut = make([]goldilocks.GoldilocksVariable, types.HASH_OUT)
	for i, v := range permutation.Squeeze() {
		if i >= types.HASH_OUT {
			break
		}
		hash.HashOut[i] = v
	}

	return hash
}

func (hasher *SpongeHasher) HashOrNoop(inputs []goldilocks.GoldilocksVariable) types.HashOutVariable {
	var hash types.HashOutVariable
	hash.HashOut = make([]goldilocks.GoldilocksVariable, types.HASH_OUT)
	if len(inputs) <= types.HASH_OUT {
		for i := 0; i < types.HASH_OUT; i++ {
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

func (hasher *SpongeHasher) TwoToOne(left types.HashOutVariable, right types.HashOutVariable) types.HashOutVariable {
	return hasher.HashNoPad(append(left.HashOut, right.HashOut...))
}
