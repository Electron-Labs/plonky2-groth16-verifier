package goldilocks

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

var CONSTANTS []*big.Int = POSEIDON_CONSTANTS()
var MDS_CIRC []*big.Int = POSEIDON_MDS_CIRC()
var MDS_DIAG []*big.Int = POSEIDON_MDS_DIAG()
var FAST_PARTIAL_FIRST_ROUND_CONSTANT []*big.Int = POSEIDON_FAST_PARTIAL_FIRST_ROUND_CONSTANT()
var FAST_PARTIAL_ROUND_CONSTANTS []*big.Int = POSEIDON_FAST_PARTIAL_ROUND_CONSTANTS()
var FAST_PARTIAL_ROUND_INITIAL_MATRIX [][]*big.Int = POSEIDON_FAST_PARTIAL_ROUND_INITIAL_MATRIX()
var FAST_PARTIAL_ROUND_W_HATS [][]*big.Int = POSEIDON_FAST_PARTIAL_ROUND_W_HATS()
var FAST_PARTIAL_ROUND_VS [][]*big.Int = POSEIDON_FAST_PARTIAL_ROUND_VS()

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
		lc := frontend.Variable(0)
		for j := 0; j < SPONGE_WIDTH; j++ {
			lc = api.Add(lc, api.Mul(MDS_CIRC[j], in[(i+j)%SPONGE_WIDTH].Limb))
		}
		lc = api.Add(lc, api.Mul(in[i].Limb, MDS_DIAG[i]))
		out[i] = Reduce(api, rangeChecker, lc, 96)
	}
	return out
}

func PartialFirstConstantLayer(api frontend.API, rangeChecker frontend.Rangechecker, in []GoldilocksVariable) []GoldilocksVariable {
	for i, v := range in {
		in[i] = Add(api, rangeChecker, v, GoldilocksVariable{Limb: FAST_PARTIAL_FIRST_ROUND_CONSTANT[i]})
	}
	return in
}

func MdsPartialLayerInit(api frontend.API, rangeChecker frontend.Rangechecker, in []GoldilocksVariable) []GoldilocksVariable {
	out := make([]GoldilocksVariable, len(in))
	out[0] = in[0]
	for i := 1; i < SPONGE_WIDTH; i++ {
		out[i] = GoldilocksVariable{Limb: 0}
	}
	for i := 1; i < SPONGE_WIDTH; i++ {
		for j := 1; j < SPONGE_WIDTH; j++ {
			out[j] = Add(api, rangeChecker, out[j], Mul(api, rangeChecker, in[i], GoldilocksVariable{Limb: FAST_PARTIAL_ROUND_INITIAL_MATRIX[i-1][j-1]}))
		}
	}
	return out
}

func MdsPartialLayerFast(api frontend.API, rangeChecker frontend.Rangechecker, in []GoldilocksVariable, r int) []GoldilocksVariable {
	out := make([]GoldilocksVariable, len(in))
	for i := range out {
		out[i] = GoldilocksVariable{Limb: 0}
	}
	d_sum := frontend.Variable(0)
	for i := 1; i < SPONGE_WIDTH; i++ {
		si := in[i].Limb
		d_sum = api.Add(d_sum, api.Mul(si, FAST_PARTIAL_ROUND_W_HATS[r][i-1]))
	}
	s0 := in[0].Limb
	mds0t0 := big.NewInt(0).Add(MDS_CIRC[0], MDS_DIAG[0])
	d_sum = api.Add(d_sum, api.Mul(s0, mds0t0))
	d := Reduce(api, rangeChecker, d_sum, 160)
	out[0] = d
	for i := 1; i < SPONGE_WIDTH; i++ {
		tmp := api.Add(in[i].Limb, api.Mul(in[0].Limb, FAST_PARTIAL_ROUND_VS[r][i-1]))
		out[i] = Reduce(api, rangeChecker, tmp, 128)
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
	state = PartialFirstConstantLayer(api, rangeChecker, state)
	state = MdsPartialLayerInit(api, rangeChecker, state)
	for i := 0; i < PARTIAL_ROUNDS; i++ {
		state[0] = Sbox(api, rangeChecker, state[0])
		state[0] = Add(api, rangeChecker, state[0], GoldilocksVariable{Limb: FAST_PARTIAL_ROUND_CONSTANTS[i]})
		state = MdsPartialLayerFast(api, rangeChecker, state, i)
	}
	*r += PARTIAL_ROUNDS
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
