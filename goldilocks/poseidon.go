package goldilocks

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

var CONSTANTS []*big.Int = POSEIDON_CONSTANTS()
var MDS_CIRC []*big.Int = POSEIDON_MDS_CIRC()
var MDS_DIAG []*big.Int = POSEIDON_MDS_DIAG()

const FULL_ROUNDS_HALF = 4
const PARTIAL_ROUNDS = 22

func Constant(api frontend.API, rangeChecker frontend.Rangechecker, in []GoldilocksVariable, r int) []GoldilocksVariable {
	for i, v := range in {
		in[i] = Add(api, rangeChecker, v, GoldilocksVariable{Limb: CONSTANTS[i+r]})
	}
	return in
}

func Sbox(api frontend.API, rangeChecker frontend.Rangechecker, in GoldilocksVariable) GoldilocksVariable {
	in2 := Mul(api, rangeChecker, in, in)
	in4 := Mul(api, rangeChecker, in2, in2)
	in3 := Mul(api, rangeChecker, in, in2)
	return Mul(api, rangeChecker, in3, in4)
}

func Mds(api frontend.API, rangeChecker frontend.Rangechecker, in []GoldilocksVariable) []GoldilocksVariable {
	out := make([]GoldilocksVariable, SPONGE_WIDTH)
	for i := 0; i < SPONGE_WIDTH; i++ {
		lc := GoldilocksVariable{Limb: 0}
		for j := 0; j < SPONGE_WIDTH; j++ {
			lc = Add(api, rangeChecker, lc, Mul(api, rangeChecker, GoldilocksVariable{Limb: MDS_CIRC[j]}, in[(i+j)%SPONGE_WIDTH]))
		}
		out[i] = Add(api, rangeChecker, lc, Mul(api, rangeChecker, in[i], GoldilocksVariable{Limb: MDS_DIAG[i]}))
	}
	return out
}

func FullRounds(api frontend.API, rangeChecker frontend.Rangechecker, state []GoldilocksVariable, r *int) []GoldilocksVariable {
	for i := 0; i < FULL_ROUNDS_HALF; i++ {
		state = Constant(api, rangeChecker, state, *r*SPONGE_WIDTH)
		for j := 0; j < SPONGE_WIDTH; j++ {
			state[j] = Sbox(api, rangeChecker, state[j])
		}
		state = Mds(api, rangeChecker, state)
		*r += 1
	}
	return state
}

func PartialRounds(api frontend.API, rangeChecker frontend.Rangechecker, state []GoldilocksVariable, r *int) []GoldilocksVariable {
	for i := 0; i < PARTIAL_ROUNDS; i++ {
		state = Constant(api, rangeChecker, state, *r*SPONGE_WIDTH)
		state[0] = Sbox(api, rangeChecker, state[0])
		state = Mds(api, rangeChecker, state)
		*r += 1
	}
	return state
}

func Permute(api frontend.API, rangeChecker frontend.Rangechecker, inputs []GoldilocksVariable) []GoldilocksVariable {
	if len(inputs) != SPONGE_WIDTH {
		panic("Invalid number of inputs")
	}

	state := make([]GoldilocksVariable, SPONGE_WIDTH)
	for j := 0; j < SPONGE_WIDTH; j++ {
		state[j] = inputs[j]
	}

	r := 0
	state = FullRounds(api, rangeChecker, state, &r)
	state = PartialRounds(api, rangeChecker, state, &r)
	state = FullRounds(api, rangeChecker, state, &r)

	if r != 2*FULL_ROUNDS_HALF+PARTIAL_ROUNDS {
		panic("Invalid number of rounds")
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
