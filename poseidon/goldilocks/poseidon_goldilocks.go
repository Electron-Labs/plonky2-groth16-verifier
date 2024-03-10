package poseidonGoldilocks

import (
	"math/big"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
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

type PoseidonGoldilocks struct{}

func Constant(api frontend.API, rangeChecker frontend.Rangechecker, in []goldilocks.GoldilocksVariable, r int) []goldilocks.GoldilocksVariable {
	for i, v := range in {
		in[i] = goldilocks.Add(api, rangeChecker, v, goldilocks.GoldilocksVariable{Limb: CONSTANTS[i+r*SPONGE_WIDTH]})
	}
	return in
}

func (poseidon *PoseidonGoldilocks) ConstantExt(api frontend.API, rangeChecker frontend.Rangechecker, in []goldilocks.GoldilocksExtension2Variable, r int) []goldilocks.GoldilocksExtension2Variable {
	in_base := make([]goldilocks.GoldilocksVariable, len(in))
	for i, v := range in {
		in_base[i] = v.A
	}
	out_base := Constant(api, rangeChecker, in_base, r)
	for i, v := range out_base {
		in[i].A = v
	}
	return in
}

func Sbox(api frontend.API, rangeChecker frontend.Rangechecker, in goldilocks.GoldilocksVariable) goldilocks.GoldilocksVariable {
	in2NoReduce := api.Mul(in.Limb, in.Limb)
	in3NoReduce := api.Mul(in.Limb, in2NoReduce)
	in3 := goldilocks.Reduce(api, rangeChecker, in3NoReduce, 192)
	in4NoReduce := api.Mul(in.Limb, in3.Limb)
	in7NoReduce := api.Mul(in3.Limb, in4NoReduce)
	in7 := goldilocks.Reduce(api, rangeChecker, in7NoReduce, 192)
	return in7
}

func (poseidon *PoseidonGoldilocks) SboxExt(api frontend.API, rangeChecker frontend.Rangechecker, in goldilocks.GoldilocksExtension2Variable) goldilocks.GoldilocksExtension2Variable {
	inVar := goldilocks.GetVariableArray(in)
	in2NoReduce := goldilocks.MulExtNoReduce(
		api,
		inVar,
		inVar,
	)
	in3NoReduce := goldilocks.MulExtNoReduce(
		api,
		in2NoReduce,
		inVar,
	)
	in3 := goldilocks.GoldilocksExtension2Variable{
		A: goldilocks.Reduce(api, rangeChecker, in3NoReduce[0], 197),
		B: goldilocks.Reduce(api, rangeChecker, in3NoReduce[1], 196),
	}
	in3Var := goldilocks.GetVariableArray(in3)
	in4NoReduce := goldilocks.MulExtNoReduce(
		api,
		inVar,
		in3Var,
	)
	in7NoReduce := goldilocks.MulExtNoReduce(
		api,
		in4NoReduce,
		in3Var,
	)
	in7 := goldilocks.GoldilocksExtension2Variable{
		A: goldilocks.Reduce(api, rangeChecker, in7NoReduce[0], 197),
		B: goldilocks.Reduce(api, rangeChecker, in7NoReduce[1], 196),
	}
	return in7
}

func Mds(api frontend.API, rangeChecker frontend.Rangechecker, in []goldilocks.GoldilocksVariable) []goldilocks.GoldilocksVariable {
	out := make([]goldilocks.GoldilocksVariable, SPONGE_WIDTH)
	for i := 0; i < SPONGE_WIDTH; i++ {
		lc := frontend.Variable(0)
		for j := 0; j < SPONGE_WIDTH; j++ {
			lc = api.Add(lc, api.Mul(MDS_CIRC[j], in[(i+j)%SPONGE_WIDTH].Limb))
		}
		lc = api.Add(lc, api.Mul(in[i].Limb, MDS_DIAG[i]))
		out[i] = goldilocks.Reduce(api, rangeChecker, lc, 96)
	}
	return out
}

func (poseidon *PoseidonGoldilocks) MdsExt(api frontend.API, rangeChecker frontend.Rangechecker, in []goldilocks.GoldilocksExtension2Variable) []goldilocks.GoldilocksExtension2Variable {
	out := make([]goldilocks.GoldilocksExtension2Variable, SPONGE_WIDTH)
	for r := 0; r < SPONGE_WIDTH; r++ {
		res := [2]frontend.Variable{0, 0}
		for i := 0; i < SPONGE_WIDTH; i++ {
			res = goldilocks.AddExtNoReduce(api, res, goldilocks.MulExtNoReduce(api, goldilocks.GetVariableArray(in[(r+i)%SPONGE_WIDTH]), [2]frontend.Variable{
				MDS_CIRC[i],
				0,
			}))
		}
		res = goldilocks.AddExtNoReduce(api, res, goldilocks.MulExtNoReduce(api, goldilocks.GetVariableArray(in[(r)%SPONGE_WIDTH]), [2]frontend.Variable{
			MDS_DIAG[r],
			0,
		}))
		out[r] = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, res[0], 73),
			B: goldilocks.Reduce(api, rangeChecker, res[1], 73),
		}
	}
	return out
}

func PartialFirstConstantLayer(api frontend.API, rangeChecker frontend.Rangechecker, in []goldilocks.GoldilocksVariable) []goldilocks.GoldilocksVariable {
	for i, v := range in {
		in[i] = goldilocks.Add(api, rangeChecker, v, goldilocks.GoldilocksVariable{Limb: FAST_PARTIAL_FIRST_ROUND_CONSTANT[i]})
	}
	return in
}

func (posiedon *PoseidonGoldilocks) PartialFirstConstantLayerExt(api frontend.API, rangeChecker frontend.Rangechecker, in []goldilocks.GoldilocksExtension2Variable) []goldilocks.GoldilocksExtension2Variable {
	in_base := make([]goldilocks.GoldilocksVariable, len(in))
	for i, v := range in {
		in_base[i] = v.A
	}
	out_base := PartialFirstConstantLayer(api, rangeChecker, in_base)
	for i, v := range out_base {
		in[i].A = v
	}
	return in
}

func MdsPartialLayerInit(api frontend.API, rangeChecker frontend.Rangechecker, in []goldilocks.GoldilocksVariable) []goldilocks.GoldilocksVariable {
	out := make([]goldilocks.GoldilocksVariable, len(in))
	outNoReduce := make([]frontend.Variable, len(in))
	out[0] = in[0]
	outNoReduce[0] = in[0].Limb
	for i := 1; i < SPONGE_WIDTH; i++ {
		out[i] = goldilocks.GoldilocksVariable{Limb: 0}
		outNoReduce[i] = 0
	}
	for i := 1; i < SPONGE_WIDTH; i++ {
		for j := 1; j < SPONGE_WIDTH; j++ {
			outNoReduce[j] = api.Add(outNoReduce[j], api.Mul(in[i].Limb, FAST_PARTIAL_ROUND_INITIAL_MATRIX[i-1][j-1]))
		}
	}
	for i := 0; i < SPONGE_WIDTH; i++ {
		out[i] = goldilocks.Reduce(api, rangeChecker, outNoReduce[i], 140)
	}
	return out
}

func (poseidon *PoseidonGoldilocks) MdsPartialLayerInitExt(api frontend.API, rangeChecker frontend.Rangechecker, in []goldilocks.GoldilocksExtension2Variable) []goldilocks.GoldilocksExtension2Variable {
	out := make([]goldilocks.GoldilocksExtension2Variable, SPONGE_WIDTH)
	outNoReduce := make([][2]frontend.Variable, SPONGE_WIDTH)
	out[0] = in[0]
	outNoReduce[0] = goldilocks.GetVariableArray(in[0])
	for i := 1; i < SPONGE_WIDTH; i++ {
		outNoReduce[i] = [2]frontend.Variable{0, 0}
	}
	for r := 1; r < SPONGE_WIDTH; r++ {
		for c := 1; c < SPONGE_WIDTH; c++ {
			outNoReduce[c] = goldilocks.AddExtNoReduce(api, outNoReduce[c], goldilocks.MulExtNoReduce(api, goldilocks.GetVariableArray(in[r]), [2]frontend.Variable{
				FAST_PARTIAL_ROUND_INITIAL_MATRIX[r-1][c-1],
				0,
			}))
		}
	}
	for i := 1; i < SPONGE_WIDTH; i++ {
		out[i] = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, outNoReduce[i][0], 131),
			B: goldilocks.Reduce(api, rangeChecker, outNoReduce[i][1], 131),
		}
	}
	return out
}

func FullRounds(api frontend.API, rangeChecker frontend.Rangechecker, state []goldilocks.GoldilocksVariable, r *int) []goldilocks.GoldilocksVariable {
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

func MdsPartialLayerFast(api frontend.API, rangeChecker frontend.Rangechecker, in []goldilocks.GoldilocksVariable, r int) []goldilocks.GoldilocksVariable {
	out := make([]goldilocks.GoldilocksVariable, len(in))
	for i := range out {
		out[i] = goldilocks.GoldilocksVariable{Limb: 0}
	}
	d_sum := frontend.Variable(0)
	for i := 1; i < SPONGE_WIDTH; i++ {
		si := in[i].Limb
		d_sum = api.Add(d_sum, api.Mul(si, FAST_PARTIAL_ROUND_W_HATS[r][i-1]))
	}
	s0 := in[0].Limb
	mds0t0 := big.NewInt(0).Add(MDS_CIRC[0], MDS_DIAG[0])
	d_sum = api.Add(d_sum, api.Mul(s0, mds0t0))
	d := goldilocks.Reduce(api, rangeChecker, d_sum, 160)
	out[0] = d
	for i := 1; i < SPONGE_WIDTH; i++ {
		tmp := api.Add(in[i].Limb, api.Mul(in[0].Limb, FAST_PARTIAL_ROUND_VS[r][i-1]))
		out[i] = goldilocks.Reduce(api, rangeChecker, tmp, 128)
	}
	return out
}

func (poseidon *PoseidonGoldilocks) MdsPartialLayerFastExt(api frontend.API, rangeChecker frontend.Rangechecker, in []goldilocks.GoldilocksExtension2Variable, r int) []goldilocks.GoldilocksExtension2Variable {
	out := make([]goldilocks.GoldilocksExtension2Variable, SPONGE_WIDTH)
	s0 := goldilocks.GetVariableArray(in[0])
	mds0to0 := big.NewInt(0).Add(MDS_CIRC[0], MDS_DIAG[0])
	d := goldilocks.MulExtNoReduce(api, s0, [2]frontend.Variable{
		mds0to0,
		0,
	})
	for i := 1; i < SPONGE_WIDTH; i++ {
		d = goldilocks.AddExtNoReduce(api, d, goldilocks.MulExtNoReduce(api, goldilocks.GetVariableArray(in[i]), [2]frontend.Variable{
			FAST_PARTIAL_ROUND_W_HATS[r][i-1],
			0,
		}))
	}
	out[0] = goldilocks.GoldilocksExtension2Variable{
		A: goldilocks.Reduce(api, rangeChecker, d[0], 131),
		B: goldilocks.Reduce(api, rangeChecker, d[1], 131),
	}
	for i := 1; i < SPONGE_WIDTH; i++ {
		res := goldilocks.AddExtNoReduce(api, goldilocks.GetVariableArray(in[i]), goldilocks.MulExtNoReduce(api, s0, [2]frontend.Variable{
			FAST_PARTIAL_ROUND_VS[r][i-1],
			0,
		}))
		out[i] = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, res[0], 128),
			B: goldilocks.Reduce(api, rangeChecker, res[1], 128),
		}
	}
	return out
}

func PartialRounds(api frontend.API, rangeChecker frontend.Rangechecker, state []goldilocks.GoldilocksVariable, r *int) []goldilocks.GoldilocksVariable {
	state = PartialFirstConstantLayer(api, rangeChecker, state)
	state = MdsPartialLayerInit(api, rangeChecker, state)
	for i := 0; i < PARTIAL_ROUNDS; i++ {
		state[0] = Sbox(api, rangeChecker, state[0])
		state[0] = goldilocks.Add(api, rangeChecker, state[0], goldilocks.GoldilocksVariable{Limb: FAST_PARTIAL_ROUND_CONSTANTS[i]})
		state = MdsPartialLayerFast(api, rangeChecker, state, i)
	}
	*r += PARTIAL_ROUNDS
	return state
}

func (poseidon *PoseidonGoldilocks) Permute(api frontend.API, rangeChecker frontend.Rangechecker, inputs []goldilocks.GoldilocksVariable) []goldilocks.GoldilocksVariable {
	if len(inputs) != SPONGE_WIDTH {
		panic("Invalid number of inputs")
	}

	state := make([]goldilocks.GoldilocksVariable, SPONGE_WIDTH)
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
