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
		in[i] = Add(api, rangeChecker, v, GoldilocksVariable{Limb: CONSTANTS[i+r*SPONGE_WIDTH]})
	}
	return in
}

func ConstantExt(api frontend.API, rangeChecker frontend.Rangechecker, in []GoldilocksExtension2Variable, r int) []GoldilocksExtension2Variable {
	in_base := make([]GoldilocksVariable, len(in))
	for i, v := range in {
		in_base[i] = v.A
	}
	out_base := Constant(api, rangeChecker, in_base, r)
	for i, v := range out_base {
		in[i].A = v
	}
	return in
}

func Sbox(api frontend.API, rangeChecker frontend.Rangechecker, in GoldilocksVariable) GoldilocksVariable {
	in2NoReduce := api.Mul(in.Limb, in.Limb)
	in3NoReduce := api.Mul(in.Limb, in2NoReduce)
	in3 := Reduce(api, rangeChecker, in3NoReduce, 192)
	in4NoReduce := api.Mul(in.Limb, in3.Limb)
	in7NoReduce := api.Mul(in3.Limb, in4NoReduce)
	in7 := Reduce(api, rangeChecker, in7NoReduce, 192)
	return in7
}

func SboxExt(api frontend.API, rangeChecker frontend.Rangechecker, in GoldilocksExtension2Variable) GoldilocksExtension2Variable {
	inVar := GetVariableArray(in)
	in2NoReduce := MulExtNoReduce(
		api,
		inVar,
		inVar,
	)
	in3NoReduce := MulExtNoReduce(
		api,
		in2NoReduce,
		inVar,
	)
	in3 := GoldilocksExtension2Variable{
		A: Reduce(api, rangeChecker, in3NoReduce[0], 197),
		B: Reduce(api, rangeChecker, in3NoReduce[1], 196),
	}
	in3Var := GetVariableArray(in3)
	in4NoReduce := MulExtNoReduce(
		api,
		inVar,
		in3Var,
	)
	in7NoReduce := MulExtNoReduce(
		api,
		in4NoReduce,
		in3Var,
	)
	in7 := GoldilocksExtension2Variable{
		A: Reduce(api, rangeChecker, in7NoReduce[0], 197),
		B: Reduce(api, rangeChecker, in7NoReduce[1], 196),
	}
	return in7
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

func MdsExt(api frontend.API, rangeChecker frontend.Rangechecker, in []GoldilocksExtension2Variable) []GoldilocksExtension2Variable {
	out := make([]GoldilocksExtension2Variable, SPONGE_WIDTH)
	for r := 0; r < SPONGE_WIDTH; r++ {
		res := [2]frontend.Variable{0, 0}
		for i := 0; i < SPONGE_WIDTH; i++ {
			res = AddExtNoReduce(api, res, MulExtNoReduce(api, GetVariableArray(in[(r+i)%SPONGE_WIDTH]), [2]frontend.Variable{
				MDS_CIRC[i],
				0,
			}))
		}
		res = AddExtNoReduce(api, res, MulExtNoReduce(api, GetVariableArray(in[(r)%SPONGE_WIDTH]), [2]frontend.Variable{
			MDS_DIAG[r],
			0,
		}))
		out[r] = GoldilocksExtension2Variable{
			A: Reduce(api, rangeChecker, res[0], 73),
			B: Reduce(api, rangeChecker, res[1], 73),
		}
	}
	return out
}

func PartialFirstConstantLayer(api frontend.API, rangeChecker frontend.Rangechecker, in []GoldilocksVariable) []GoldilocksVariable {
	for i, v := range in {
		in[i] = Add(api, rangeChecker, v, GoldilocksVariable{Limb: FAST_PARTIAL_FIRST_ROUND_CONSTANT[i]})
	}
	return in
}

func PartialFirstConstantLayerExt(api frontend.API, rangeChecker frontend.Rangechecker, in []GoldilocksExtension2Variable) []GoldilocksExtension2Variable {
	in_base := make([]GoldilocksVariable, len(in))
	for i, v := range in {
		in_base[i] = v.A
	}
	out_base := PartialFirstConstantLayer(api, rangeChecker, in_base)
	for i, v := range out_base {
		in[i].A = v
	}
	return in
}

func MdsPartialLayerInit(api frontend.API, rangeChecker frontend.Rangechecker, in []GoldilocksVariable) []GoldilocksVariable {
	out := make([]GoldilocksVariable, len(in))
	outNoReduce := make([]frontend.Variable, len(in))
	out[0] = in[0]
	outNoReduce[0] = in[0].Limb
	for i := 1; i < SPONGE_WIDTH; i++ {
		out[i] = GoldilocksVariable{Limb: 0}
		outNoReduce[i] = 0
	}
	for i := 1; i < SPONGE_WIDTH; i++ {
		for j := 1; j < SPONGE_WIDTH; j++ {
			outNoReduce[j] = api.Add(outNoReduce[j], api.Mul(in[i].Limb, FAST_PARTIAL_ROUND_INITIAL_MATRIX[i-1][j-1]))
		}
	}
	for i := 0; i < SPONGE_WIDTH; i++ {
		out[i] = Reduce(api, rangeChecker, outNoReduce[i], 140)
	}
	return out
}

func MdsPartialLayerInitExt(api frontend.API, rangeChecker frontend.Rangechecker, in []GoldilocksExtension2Variable) []GoldilocksExtension2Variable {
	out := make([]GoldilocksExtension2Variable, SPONGE_WIDTH)
	outNoReduce := make([][2]frontend.Variable, SPONGE_WIDTH)
	out[0] = in[0]
	outNoReduce[0] = GetVariableArray(in[0])
	for i := 1; i < SPONGE_WIDTH; i++ {
		outNoReduce[i] = [2]frontend.Variable{0, 0}
	}
	for r := 1; r < SPONGE_WIDTH; r++ {
		for c := 1; c < SPONGE_WIDTH; c++ {
			outNoReduce[c] = AddExtNoReduce(api, outNoReduce[c], MulExtNoReduce(api, GetVariableArray(in[r]), [2]frontend.Variable{
				FAST_PARTIAL_ROUND_INITIAL_MATRIX[r-1][c-1],
				0,
			}))
		}
	}
	for i := 1; i < SPONGE_WIDTH; i++ {
		out[i] = GoldilocksExtension2Variable{
			A: Reduce(api, rangeChecker, outNoReduce[i][0], 131),
			B: Reduce(api, rangeChecker, outNoReduce[i][1], 131),
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

func MdsPartialLayerFastExt(api frontend.API, rangeChecker frontend.Rangechecker, in []GoldilocksExtension2Variable, r int) []GoldilocksExtension2Variable {
	out := make([]GoldilocksExtension2Variable, SPONGE_WIDTH)
	s0 := GetVariableArray(in[0])
	mds0to0 := big.NewInt(0).Add(MDS_CIRC[0], MDS_DIAG[0])
	d := MulExtNoReduce(api, s0, [2]frontend.Variable{
		mds0to0,
		0,
	})
	for i := 1; i < SPONGE_WIDTH; i++ {
		d = AddExtNoReduce(api, d, MulExtNoReduce(api, GetVariableArray(in[i]), [2]frontend.Variable{
			FAST_PARTIAL_ROUND_W_HATS[r][i-1],
			0,
		}))
	}
	out[0] = GoldilocksExtension2Variable{
		A: Reduce(api, rangeChecker, d[0], 131),
		B: Reduce(api, rangeChecker, d[1], 131),
	}
	for i := 1; i < SPONGE_WIDTH; i++ {
		res := AddExtNoReduce(api, GetVariableArray(in[i]), MulExtNoReduce(api, s0, [2]frontend.Variable{
			FAST_PARTIAL_ROUND_VS[r][i-1],
			0,
		}))
		out[i] = GoldilocksExtension2Variable{
			A: Reduce(api, rangeChecker, res[0], 128),
			B: Reduce(api, rangeChecker, res[1], 128),
		}
	}
	return out
}

func FullRounds(api frontend.API, rangeChecker frontend.Rangechecker, state []GoldilocksVariable, r *int) []GoldilocksVariable {
	for i := 0; i < FULL_ROUNDS_HALF; i++ {
		state = Constant(api, rangeChecker, state, *r)
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
