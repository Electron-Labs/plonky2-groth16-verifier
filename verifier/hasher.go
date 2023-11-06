package verifier

import (
	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark/frontend"
)

type SpongeHasher struct {
	api          frontend.API
	rangeChecker frontend.Rangechecker
}

func NewHasher(api frontend.API, rangeChecker frontend.Rangechecker) SpongeHasher {
	return SpongeHasher{
		api:          api,
		rangeChecker: rangeChecker,
	}
}

func (hasher *SpongeHasher) HashNoPad(inputs []goldilocks.GoldilocksVariable) HashOutVariable {
	permutation := goldilocks.NewPermutation(hasher.api, hasher.rangeChecker)

	numInputs := len(inputs)
	numChunks := (numInputs-1)/goldilocks.SPONGE_RATE + 1
	for i := 0; i < numChunks; i++ {
		start := i * goldilocks.SPONGE_RATE
		end := min((i+1)*goldilocks.SPONGE_RATE, numInputs)
		permutation.Set(inputs[start:end])
		permutation.Permute()
	}

	var hash HashOutVariable
	hash.HashOut = make([]goldilocks.GoldilocksVariable, HASH_OUT)
	for i, v := range permutation.Squeeze() {
		if i >= HASH_OUT {
			break
		}
		hash.HashOut[i] = v
	}

	return hash
}
