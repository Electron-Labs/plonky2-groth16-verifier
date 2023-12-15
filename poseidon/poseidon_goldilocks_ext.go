package poseidon

// import (
// 	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
// 	"github.com/consensys/gnark/frontend"
// )

// type PoseidonGoldilocksExt struct{}

// func (poseidon *PoseidonGoldilocksExt) PartialFirstConstantLayer(api frontend.API, rangeChecker frontend.Rangechecker, in []goldilocks.GoldilocksExtension2Variable) []goldilocks.GoldilocksExtension2Variable {
// 	in_base := make([]goldilocks.GoldilocksVariable, len(in))
// 	for i, v := range in {
// 		in_base[i] = v.A
// 	}
// 	out_base := PartialFirstConstantLayer(api, rangeChecker, in_base)
// 	for i, v := range out_base {
// 		in[i].A = v
// 	}
// 	return in
// }

// func (poseidon *PoseidonGoldilocksExt) MdsPartialLayerInit(api frontend.API, rangeChecker frontend.Rangechecker, in []goldilocks.GoldilocksExtension2Variable) []goldilocks.GoldilocksExtension2Variable {
// 	out := make([]goldilocks.GoldilocksExtension2Variable, SPONGE_WIDTH)
// 	outNoReduce := make([][2]frontend.Variable, SPONGE_WIDTH)
// 	out[0] = in[0]
// 	outNoReduce[0] = goldilocks.GetVariableArray(in[0])
// 	for i := 1; i < SPONGE_WIDTH; i++ {
// 		outNoReduce[i] = [2]frontend.Variable{0, 0}
// 	}
// 	for r := 1; r < SPONGE_WIDTH; r++ {
// 		for c := 1; c < SPONGE_WIDTH; c++ {
// 			outNoReduce[c] = goldilocks.AddExtNoReduce(api, outNoReduce[c], goldilocks.MulExtNoReduce(api, goldilocks.GetVariableArray(in[r]), [2]frontend.Variable{
// 				FAST_PARTIAL_ROUND_INITIAL_MATRIX[r-1][c-1],
// 				0,
// 			}))
// 		}
// 	}
// 	for i := 1; i < SPONGE_WIDTH; i++ {
// 		out[i] = goldilocks.GoldilocksExtension2Variable{
// 			A: goldilocks.Reduce(api, rangeChecker, outNoReduce[i][0], 131),
// 			B: goldilocks.Reduce(api, rangeChecker, outNoReduce[i][1], 131),
// 		}
// 	}
// 	return out
// }

// func (poseidon *PoseidonGoldilocksExt) Sbox(api frontend.API, rangeChecker frontend.Rangechecker, in goldilocks.GoldilocksExtension2Variable) goldilocks.GoldilocksExtension2Variable {
// 	inVar := goldilocks.GetVariableArray(in)
// 	in2NoReduce := goldilocks.MulExtNoReduce(
// 		api,
// 		inVar,
// 		inVar,
// 	)
// 	in3NoReduce := goldilocks.MulExtNoReduce(
// 		api,
// 		in2NoReduce,
// 		inVar,
// 	)
// 	in3 := goldilocks.GoldilocksExtension2Variable{
// 		A: goldilocks.Reduce(api, rangeChecker, in3NoReduce[0], 197),
// 		B: goldilocks.Reduce(api, rangeChecker, in3NoReduce[1], 196),
// 	}
// 	in3Var := goldilocks.GetVariableArray(in3)
// 	in4NoReduce := goldilocks.MulExtNoReduce(
// 		api,
// 		inVar,
// 		in3Var,
// 	)
// 	in7NoReduce := goldilocks.MulExtNoReduce(
// 		api,
// 		in4NoReduce,
// 		in3Var,
// 	)
// 	in7 := goldilocks.GoldilocksExtension2Variable{
// 		A: goldilocks.Reduce(api, rangeChecker, in7NoReduce[0], 197),
// 		B: goldilocks.Reduce(api, rangeChecker, in7NoReduce[1], 196),
// 	}
// 	return in7
// }

// func (poseidon *PoseidonGoldilocksExt) Mds(api frontend.API, rangeChecker frontend.Rangechecker, in []goldilocks.GoldilocksExtension2Variable) []goldilocks.GoldilocksExtension2Variable {
// 	out := make([]goldilocks.GoldilocksExtension2Variable, SPONGE_WIDTH)
// 	for r := 0; r < SPONGE_WIDTH; r++ {
// 		res := [2]frontend.Variable{0, 0}
// 		for i := 0; i < SPONGE_WIDTH; i++ {
// 			res = goldilocks.AddExtNoReduce(api, res, goldilocks.MulExtNoReduce(api, goldilocks.GetVariableArray(in[(r+i)%SPONGE_WIDTH]), [2]frontend.Variable{
// 				MDS_CIRC[i],
// 				0,
// 			}))
// 		}
// 		res = goldilocks.AddExtNoReduce(api, res, goldilocks.MulExtNoReduce(api, goldilocks.GetVariableArray(in[(r)%SPONGE_WIDTH]), [2]frontend.Variable{
// 			MDS_DIAG[r],
// 			0,
// 		}))
// 		out[r] = goldilocks.GoldilocksExtension2Variable{
// 			A: goldilocks.Reduce(api, rangeChecker, res[0], 73),
// 			B: goldilocks.Reduce(api, rangeChecker, res[1], 73),
// 		}
// 	}
// 	return out
// }

// func (poseidon *PoseidonGoldilocksExt) PartialFirstConstantLayer(api frontend.API, rangeChecker frontend.Rangechecker, in []goldilocks.GoldilocksExtension2Variable) []goldilocks.GoldilocksExtension2Variable {
// 	in_base := make([]goldilocks.GoldilocksVariable, len(in))
// 	for i, v := range in {
// 		in_base[i] = v.A
// 	}
// 	let poseidon_goldilocks := &posedposeidon.Po
// 	out_base := PartialFirstConstantLayer(api, rangeChecker, in_base)
// 	for i, v := range out_base {
// 		in[i].A = v
// 	}
// 	return in
// }

// // func (poseidon *PoseidonGoldilocksExt) PartialRounds(api frontend.API, rangeChecker frontend.Rangechecker, state []goldilocks.GoldilocksExtension2Variable, r *int) []goldilocks.GoldilocksExtension2Variable {
// // 	state = poseidon.PartialFirstConstantLayer(api, rangeChecker, state)
// // 	state = poseidon.MdsPartialLayerInit(api, rangeChecker, state)
// // 	for i := 0; i < PARTIAL_ROUNDS; i++ {
// // 		state[0] = poseidon.Sbox(api, rangeChecker, state[0])
// // 		state[0] = goldilocks.Add(api, rangeChecker, state[0], goldilocks.GoldilocksVariable{Limb: FAST_PARTIAL_ROUND_CONSTANTS[i]})
// // 		state = MdsPartialLayerFast(api, rangeChecker, state, i)
// // 	}
// // 	*r += PARTIAL_ROUNDS
// // 	return state
// // }

// func (poseidon *PoseidonGoldilocksExt) PermuteWithState(api frontend.API, rangeChecker frontend.Rangechecker, inputs []goldilocks.GoldilocksExtension2Variable) []goldilocks.GoldilocksExtension2Variable {
// 	if len(inputs) != SPONGE_WIDTH {
// 		panic("Invalid number of inputs")
// 	}

// 	// state := make([]goldilocks.GoldilocksVariable, SPONGE_WIDTH)
// 	// for j := 0; j < SPONGE_WIDTH; j++ {
// 	// 	state[j] = inputs[j]
// 	// }

// 	// r := 0
// 	// 	state = FullRounds(api, rangeChecker, state, &r)
// 	// 	state = PartialRounds(api, rangeChecker, state, &r)
// 	// 	state = FullRounds(api, rangeChecker, state, &r)

// 	// 	if r != 2*FULL_ROUNDS_HALF+PARTIAL_ROUNDS {
// 	// 		panic("Invalid number of rounds")
// 	// 	}

// 	// return state
// }
