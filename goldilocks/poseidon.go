package goldilocks

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

func Constant(api frontend.API, rangeChecker frontend.Rangechecker, in []GoldilocksVariable, c []*big.Int, r int) []GoldilocksVariable {
	out := make([]GoldilocksVariable, SPONGE_WIDTH)
	for i, v := range in {
		out[i] = Add(api, rangeChecker, v, GoldilocksVariable{Limb: c[i+r]})
	}
	return out
}

func Sbox(api frontend.API, rangeChecker frontend.Rangechecker, in GoldilocksVariable) GoldilocksVariable {
	in2 := Mul(api, rangeChecker, in, in)
	in4 := Mul(api, rangeChecker, in2, in2)
	in3 := Mul(api, rangeChecker, in, in2)
	return Mul(api, rangeChecker, in3, in4)
}

func Mds(api frontend.API, rangeChecker frontend.Rangechecker, in []GoldilocksVariable, mds_circ []*big.Int, mds_diag []*big.Int) []GoldilocksVariable {
	out := make([]GoldilocksVariable, SPONGE_WIDTH)
	for i := 0; i < SPONGE_WIDTH; i++ {
		lc := GoldilocksVariable{Limb: 0}
		for j := 0; j < SPONGE_WIDTH; j++ {
			lc = Add(api, rangeChecker, lc, Mul(api, rangeChecker, GoldilocksVariable{Limb: mds_circ[j]}, in[(i+j)%SPONGE_WIDTH]))
		}
		out[i] = Add(api, rangeChecker, lc, Mul(api, rangeChecker, in[i], GoldilocksVariable{Limb: mds_diag[i]}))
	}
	return out
}

func Permute(api frontend.API, rangeChecker frontend.Rangechecker, inputs []GoldilocksVariable) []GoldilocksVariable {
	if len(inputs) != SPONGE_WIDTH {
		panic("Invalid number of inputs")
	}
	full_rounds_half := 4
	partial_rounds := 22
	constants := POSEIDON_CONSTANTS()
	if len(constants) != MAX_WIDTH*N_ROUNDS {
		panic("Incorrect number of constants")
	}
	mds_circ := POSEIDON_MDS_CIRC()
	if len(mds_circ) != SPONGE_WIDTH {
		panic("Incorrect number of constants")
	}
	mds_diag := POSEIDON_MDS_DIAG()
	if len(mds_diag) != SPONGE_WIDTH {
		panic("Incorrect number of constants")
	}

	state := make([]GoldilocksVariable, SPONGE_WIDTH)
	for j := 0; j < SPONGE_WIDTH; j++ {
		state[j] = inputs[j]
	}

	r := 0
	for i := 0; i < full_rounds_half; i++ {
		state = Constant(api, rangeChecker, state, constants, r*SPONGE_WIDTH)
		for j := 0; j < SPONGE_WIDTH; j++ {
			state[j] = Sbox(api, rangeChecker, state[j])
		}
		state = Mds(api, rangeChecker, state, mds_circ, mds_diag)
		r += 1
	}

	for i := 0; i < partial_rounds; i++ {
		state = Constant(api, rangeChecker, state, constants, r*SPONGE_WIDTH)
		state[0] = Sbox(api, rangeChecker, state[0])
		state = Mds(api, rangeChecker, state, mds_circ, mds_diag)
		r += 1
	}

	for i := 0; i < full_rounds_half; i++ {
		state = Constant(api, rangeChecker, state, constants, r*SPONGE_WIDTH)
		for j := 0; j < SPONGE_WIDTH; j++ {
			state[j] = Sbox(api, rangeChecker, state[j])
		}
		state = Mds(api, rangeChecker, state, mds_circ, mds_diag)
		r += 1
	}
	return state
}

type Permutation struct {
	api          frontend.API
	rangeChecker frontend.Rangechecker
	state        []GoldilocksVariable
}

func NewPermutation(api frontend.API, rangeChecker frontend.Rangechecker) Permutation {
	state := make([]GoldilocksVariable, SPONGE_WIDTH)
	for i := 0; i < SPONGE_WIDTH; i++ {
		state[i] = GoldilocksVariable{Limb: 0}
	}
	return Permutation{
		api:          api,
		rangeChecker: rangeChecker,
		state:        state,
	}
}

func (hasher *Permutation) Set(inputs []GoldilocksVariable) {
	if len(inputs) > SPONGE_WIDTH {
		panic("Invalid number of inputs")
	}
	for i, v := range inputs {
		hasher.state[i] = v
	}
}

func (hasher *Permutation) Permute() {
	hasher.state = Permute(hasher.api, hasher.rangeChecker, hasher.state)
}

func (hasher *Permutation) Squeeze() []GoldilocksVariable {
	return hasher.state[:SPONGE_RATE]
}
