package gates

import (
	"fmt"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/Electron-Labs/plonky2-groth16-verifier/poseidon"
	"github.com/consensys/gnark/frontend"
)

const WIRE_SWAP = 2 * poseidon.SPONGE_WIDTH
const START_DELTA = 2*poseidon.SPONGE_WIDTH + 1
const START_FULL_0 = START_DELTA + 4
const START_PARTIAL = START_FULL_0 + poseidon.SPONGE_WIDTH*(poseidon.FULL_ROUNDS_HALF-1)
const START_FULL_1 = START_PARTIAL + poseidon.PARTIAL_ROUNDS

type PoseidonGate struct {
	poseidon poseidon.Poseidon
}

func NewPoseidonGate(id string) *PoseidonGate {
	if id != "PoseidonGate(PhantomData<plonky2_field::goldilocks_field::GoldilocksField>)<WIDTH=12>" {
		panic(fmt.Sprintln("Invalid gate id: ", id))
	}
	poseidon_goldilocks := &poseidon.PoseidonGoldilocks{}
	return &PoseidonGate{
		poseidon: poseidon_goldilocks,
	}
}

func (gate *PoseidonGate) EvalUnfiltered(api frontend.API, rangeChecker frontend.Rangechecker, vars EvaluationVars) []goldilocks.GoldilocksExtension2Variable {
	constraints := make([]goldilocks.GoldilocksExtension2Variable, 0, gate.num_constraints())
	swap := vars.LocalWires[WIRE_SWAP]
	swapVar := goldilocks.GetVariableArray(swap)
	no_reduce_c := goldilocks.SubExtNoReduce(
		api,
		swapVar,
		[2]frontend.Variable{1, 0},
	)
	no_reduce_c = goldilocks.MulExtNoReduce(
		api,
		swapVar,
		no_reduce_c,
	)
	constraints = append(constraints, goldilocks.GoldilocksExtension2Variable{
		A: goldilocks.Reduce(api, rangeChecker, no_reduce_c[0], 132),
		B: goldilocks.Reduce(api, rangeChecker, no_reduce_c[1], 130),
	})
	for i := 0; i < 4; i++ {
		input_lhs := vars.LocalWires[gate.wire_input(i)]
		input_rhs := vars.LocalWires[gate.wire_input(i+4)]
		delta_i := vars.LocalWires[gate.wire_delta(i)]
		no_reduce_c = goldilocks.SubExtNoReduce(
			api,
			goldilocks.GetVariableArray(input_rhs),
			goldilocks.GetVariableArray(input_lhs),
		)
		no_reduce_c = goldilocks.MulExtNoReduce(
			api,
			swapVar,
			no_reduce_c,
		)
		no_reduce_c = goldilocks.SubExtNoReduce(
			api,
			no_reduce_c,
			goldilocks.GetVariableArray(delta_i),
		)
		constraints = append(constraints, goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, no_reduce_c[0], 132),
			B: goldilocks.Reduce(api, rangeChecker, no_reduce_c[1], 130),
		})
	}
	state := make([]goldilocks.GoldilocksExtension2Variable, poseidon.SPONGE_WIDTH)
	for i := 0; i < 4; i++ {
		delta_i := vars.LocalWires[gate.wire_delta(i)]
		input_lhs := vars.LocalWires[gate.wire_input(i)]
		input_rhs := vars.LocalWires[gate.wire_input(i+4)]
		state[i] = goldilocks.AddExt(api, rangeChecker, input_lhs, delta_i)
		state[i+4] = goldilocks.SubExt(api, rangeChecker, input_rhs, delta_i)
	}
	for i := 8; i < poseidon.SPONGE_WIDTH; i++ {
		state[i] = vars.LocalWires[gate.wire_input(i)]
	}

	round_ctr := 0
	// FULL ROUNDS
	for r := 0; r < poseidon.FULL_ROUNDS_HALF; r++ {
		state = gate.poseidon.ConstantExt(api, rangeChecker, state, round_ctr)
		if r != 0 {
			for i := 0; i < poseidon.SPONGE_WIDTH; i++ {
				sbox_in := vars.LocalWires[gate.wire_full_sbox_0(r, i)]
				constraints = append(constraints, goldilocks.SubExt(api, rangeChecker, state[i], sbox_in))
				state[i] = sbox_in
			}
		}
		for i := 0; i < poseidon.SPONGE_WIDTH; i++ {
			state[i] = gate.poseidon.SboxExt(api, rangeChecker, state[i])
		}
		state = gate.poseidon.MdsExt(api, rangeChecker, state)
		round_ctr += 1
	}

	// PARTIAL ROUNDS
	state = gate.poseidon.PartialFirstConstantLayerExt(api, rangeChecker, state)
	state = gate.poseidon.MdsPartialLayerInitExt(api, rangeChecker, state)
	for r := 0; r < poseidon.PARTIAL_ROUNDS-1; r++ {
		sbox_in := vars.LocalWires[gate.wire_partial_sbox(r)]
		constraints = append(constraints, goldilocks.SubExt(api, rangeChecker, state[0], sbox_in))
		state[0] = gate.poseidon.SboxExt(api, rangeChecker, sbox_in)
		state[0].A = goldilocks.Add(api, rangeChecker, state[0].A, goldilocks.GoldilocksVariable{Limb: poseidon.FAST_PARTIAL_ROUND_CONSTANTS[r]})
		state = gate.poseidon.MdsPartialLayerFastExt(api, rangeChecker, state, r)
	}
	sbox_in := vars.LocalWires[gate.wire_partial_sbox(poseidon.PARTIAL_ROUNDS-1)]
	constraints = append(constraints, goldilocks.SubExt(api, rangeChecker, state[0], sbox_in))
	state[0] = gate.poseidon.SboxExt(api, rangeChecker, sbox_in)
	state = gate.poseidon.MdsPartialLayerFastExt(api, rangeChecker, state, poseidon.PARTIAL_ROUNDS-1)
	round_ctr += poseidon.PARTIAL_ROUNDS

	//FULL ROUNDS
	for r := 0; r < poseidon.FULL_ROUNDS_HALF; r++ {
		state = gate.poseidon.ConstantExt(api, rangeChecker, state, round_ctr)
		for i := 0; i < poseidon.SPONGE_WIDTH; i++ {
			sbox_in := vars.LocalWires[gate.wire_full_sbox_1(r, i)]
			constraints = append(constraints, goldilocks.SubExt(api, rangeChecker, state[i], sbox_in))
			state[i] = sbox_in
		}
		for i := 0; i < poseidon.SPONGE_WIDTH; i++ {
			state[i] = gate.poseidon.SboxExt(api, rangeChecker, state[i])
		}
		state = gate.poseidon.MdsExt(api, rangeChecker, state)
		round_ctr += 1
	}

	for i := 0; i < poseidon.SPONGE_WIDTH; i++ {
		constraints = append(constraints, goldilocks.SubExt(api, rangeChecker, state[i], vars.LocalWires[gate.wire_output(i)]))
	}

	return constraints
}

func (gate *PoseidonGate) num_constraints() int {
	return poseidon.SPONGE_WIDTH*(poseidon.FULL_ROUNDS_HALF*2-1) + poseidon.PARTIAL_ROUNDS + poseidon.SPONGE_WIDTH + 1 + 4
}

func (gate *PoseidonGate) wire_input(i int) int {
	return i
}

func (gate *PoseidonGate) wire_delta(i int) int {
	return START_DELTA + i
}

func (gate *PoseidonGate) wire_full_sbox_0(round int, i int) int {
	return START_FULL_0 + poseidon.SPONGE_WIDTH*(round-1) + i
}

func (gate *PoseidonGate) wire_output(i int) int {
	return poseidon.SPONGE_WIDTH + i
}

func (gate *PoseidonGate) wire_partial_sbox(i int) int {
	return START_PARTIAL + i
}

func (gate *PoseidonGate) wire_full_sbox_1(round int, i int) int {
	return START_FULL_1 + poseidon.SPONGE_WIDTH*round + i
}
