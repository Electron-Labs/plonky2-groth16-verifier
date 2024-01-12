package hash

import (
	"math/big"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	poseidonBn254 "github.com/Electron-Labs/plonky2-groth16-verifier/poseidon/bn254"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/types"
	"github.com/consensys/gnark/frontend"
)

const GOLDILOCKS_ELEMENTS = 3

type PoseidonBn254Hasher struct {
	api      frontend.API
	poseidon poseidonBn254.Poseidon
}

func NewPoseidonBn254Hasher(api frontend.API, poseidon poseidonBn254.Poseidon) PoseidonBn254Hasher {
	return PoseidonBn254Hasher{
		api:      api,
		poseidon: poseidon,
	}
}

func getBigTen64() *big.Int {
	bigTen63 := new(big.Int).SetUint64(1 << 63)
	bigTen := new(big.Int).SetUint64(1 << 1)
	return new(big.Int).Mul(bigTen63, bigTen)
}

func (hasher *PoseidonBn254Hasher) HashNoPad(api frontend.API, inputs []goldilocks.GoldilocksVariable) types.PoseidonBn254HashOut {
	permutation := poseidonBn254.NewPermutation(hasher.api, hasher.poseidon)

	bigTen64 := getBigTen64()

	for i := 0; i < len(inputs); i += poseidonBn254.RATE * 3 {
		end_i := min(len(inputs), i+poseidonBn254.RATE*3)
		rateChunk := inputs[i:end_i]

		for j := 0; j < len(rateChunk); j += 3 {
			end_j := min(len(rateChunk), j+3)
			bn254Chunk := rateChunk[j:end_j]

			stateBn254 := frontend.Variable(0)
			var k int64
			for k = 0; k < int64(len(bn254Chunk)); k++ {
				stateBn254 = api.MulAcc(stateBn254, bn254Chunk[k].Limb, new(big.Int).Exp(bigTen64, new(big.Int).SetInt64(k), nil))
			}

			permutation.Set(j/3+1, stateBn254)
		}
		permutation.Permute()
	}

	return types.PoseidonBn254HashOut{HashOut: permutation.Squeeze()[0]} // taking first element as POSEIDON_Bn254_HASH_OUT = 1
}

func (hasher *PoseidonBn254Hasher) HashOrNoop(api frontend.API, inputs []goldilocks.GoldilocksVariable) types.PoseidonBn254HashOut {
	if len(inputs) <= GOLDILOCKS_ELEMENTS {
		bigTen64 := getBigTen64()
		hashBn254 := frontend.Variable(0)
		var i int64
		for i = 0; i < int64(len(inputs)); i++ {
			hashBn254 = api.MulAcc(hashBn254, inputs[i].Limb, new(big.Int).Exp(bigTen64, new(big.Int).SetInt64(i), nil))
		}
		return types.PoseidonBn254HashOut{HashOut: hashBn254}
	} else {
		return hasher.HashNoPad(api, inputs)
	}
}

func (hasher *PoseidonBn254Hasher) TwoToOne(api frontend.API, left types.PoseidonBn254HashOut, right types.PoseidonBn254HashOut) types.PoseidonBn254HashOut {
	permutation := poseidonBn254.NewPermutation(hasher.api, hasher.poseidon)

	permutation.Set(0, frontend.Variable(0))
	permutation.Set(1, frontend.Variable(0))
	permutation.Set(2, left.HashOut)
	permutation.Set(3, right.HashOut)

	permutation.Permute()
	return types.PoseidonBn254HashOut{HashOut: permutation.Squeeze()[0]}
}
