package hash

import (
	"slices"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	poseidonBn254 "github.com/Electron-Labs/plonky2-groth16-verifier/poseidon/bn254"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/types"
	"github.com/consensys/gnark/frontend"
)

const GOLDILOCKS_ELEMENTS = 3

type PoseidonBn254Hasher struct {
	api          frontend.API
	rangeChecker frontend.Rangechecker
	poseidon     poseidonBn254.Poseidon
}

func NewPoseidonBn254Hasher(api frontend.API, rangeChecker frontend.Rangechecker, poseidon poseidonBn254.Poseidon) PoseidonBn254Hasher {
	return PoseidonBn254Hasher{
		api:          api,
		rangeChecker: rangeChecker,
		poseidon:     poseidon,
	}
}

func (hasher *PoseidonBn254Hasher) HashNoPad(api frontend.API, inputs []goldilocks.GoldilocksVariable) types.PoseidonBn254HashOut {
	permutation := poseidonBn254.NewPermutation(hasher.api, hasher.poseidon)

	for i := 0; i < len(inputs); i += poseidonBn254.RATE * 3 {
		end_i := min(len(inputs), i+poseidonBn254.RATE*3)
		rateChunk := inputs[i:end_i]

		for j := 0; j < len(rateChunk); j += 3 {
			end_j := min(len(rateChunk), j+3)
			bn254Chunk := rateChunk[j:end_j]

			bytesLe := make([]byte, 32)
			for k := 0; k < 3; k++ {
				copy(bytesLe[k*8:(k+1)*8], goldilocks.GetBytesLe(api, bn254Chunk[k]))
			}

			for n := 0; n < 8; n++ {
				bytesLe[24+n] = 0
			}

			// get `bytesLe` in big endian
			bytesBe := make([]byte, 32)
			copy(bytesBe, bytesLe)
			slices.Reverse(bytesBe)

			stateBigInt := api.Compiler().Field().SetBytes(bytesBe)
			stateBn254 := frontend.Variable(stateBigInt)
			permutation.Set(j/3+1, stateBn254)
		}
		permutation.Permute()
	}

	return types.PoseidonBn254HashOut{HashOut: permutation.Squeeze()[0]} // taking first element as POSEIDON_Bn254_HASH_OUT = 1
}

func (hasher *PoseidonBn254Hasher) HashOrNoop(api frontend.API, inputs []goldilocks.GoldilocksVariable) types.PoseidonBn254HashOut {
	if len(inputs) <= GOLDILOCKS_ELEMENTS {
		inputsBytes := make([]byte, 32)
		for i := 0; i < len(inputs); i++ {
			bytesLe := goldilocks.GetBytesLe(api, inputs[i])
			copy(inputsBytes[i*8:(i+1)*8], bytesLe)
		}

		for i := len(inputs) * 8; i < 32; i++ {
			inputsBytes[i] = 0
		}

		// get `inputsBytes` in big endian
		inputsBytesBe := make([]byte, 32)
		copy(inputsBytesBe, inputsBytes)
		slices.Reverse(inputsBytesBe)

		hashBn254 := api.Compiler().Field().SetBytes(inputsBytesBe)
		return types.PoseidonBn254HashOut{HashOut: hashBn254}
	} else {
		return hasher.HashNoPad(api, inputs)
	}
}

func (hasher *PoseidonBn254Hasher) TwoToOne(api frontend.API, left types.PoseidonBn254HashOut, right types.PoseidonBn254HashOut) types.PoseidonBn254HashOut {
	permutation := poseidonBn254.NewPermutation(hasher.api, hasher.poseidon)

	permutation.Set(0, frontend.Variable(0))
	permutation.Set(2, frontend.Variable(0))
	permutation.Set(1, left.HashOut)
	permutation.Set(1, right.HashOut)

	permutation.Permute()
	return types.PoseidonBn254HashOut{HashOut: permutation.Squeeze()[0]}
}
