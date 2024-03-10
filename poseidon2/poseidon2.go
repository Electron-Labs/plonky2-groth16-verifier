package poseidon2

import (
	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark/frontend"
)

type Poseidon2Goldilocks struct{}

func MatmulM4(api frontend.API, rangeChecker frontend.Rangechecker, inputs []goldilocks.GoldilocksVariable) {
	const t4 = WIDTH / 4
	for i := 0; i < t4; i++ {
		start_index := i * 4
		t_0 := api.Add(inputs[start_index].Limb, inputs[start_index+1].Limb)
		t_1 := api.Add(inputs[start_index+2].Limb, inputs[start_index+3].Limb)
		t_2 := api.Mul(t_1, 1)

		t_2Copy := api.Mul(t_2, 1)
		t_2 = api.MulAcc(t_2Copy, inputs[start_index+1].Limb, 2)

		t_3 := api.Mul(t_0, 1)

		t_3Copy := api.Mul(t_3, 1)
		t_3 = api.MulAcc(t_3Copy, inputs[start_index+3].Limb, 2)

		t_4 := api.Mul(t_3, 1)

		t_4Copy := api.Mul(t_4, 1)
		t_4 = api.MulAcc(t_4Copy, t_1, 4)

		t_5 := api.Mul(t_2, 1)

		t_5Copy := api.Mul(t_5, 1)
		t_5 = api.MulAcc(t_5Copy, t_0, 4)

		// t2 -> 66
		// t3 -> 66
		// t4 -> 67
		// t5 -> 67
		inputs[start_index] = goldilocks.Reduce(api, rangeChecker, api.Add(t_3, t_5), 68)
		inputs[start_index+1] = goldilocks.Reduce(api, rangeChecker, t_5, 67)
		inputs[start_index+2] = goldilocks.Reduce(api, rangeChecker, api.Add(t_2, t_4), 68)
		inputs[start_index+3] = goldilocks.Reduce(api, rangeChecker, t_4, 67)
	}
}

func MatmulExternal(api frontend.API, rangeChecker frontend.Rangechecker, inputs []goldilocks.GoldilocksVariable) {
	// Applying cheap 4x4 MDS matrix to each 4-element part of the state
	MatmulM4(api, rangeChecker, inputs)

	// Applying second cheap matrix for t > 4
	// Compute store = [M4, M4, M4] * x
	t4 := WIDTH / 4
	storedNoReduce := make([]frontend.Variable, 4)

	for l := 0; l < 4; l++ {
		storedNoReduce[l] = inputs[l].Limb
		for j := 1; j < t4; j++ {
			storedNoReduce[l] = api.Add(storedNoReduce[l], inputs[4*j+l].Limb)
		}
	}

	// Compute store + circ[M4,0,0] * X
	inputsNoReduce := make([]frontend.Variable, len(inputs))
	for i := 0; i < len(inputs); i++ {
		inputsNoReduce[i] = api.Add(inputs[i].Limb, storedNoReduce[i%4])
	}
	for l := 0; l < len(inputs); l++ {
		inputs[l] = goldilocks.Reduce(api, rangeChecker, inputsNoReduce[l], 66)
	}
}

func MatmulInternal(api frontend.API, rangeChecker frontend.Rangechecker, inputs []goldilocks.GoldilocksVariable) {
	// state := make([]goldilocks.GoldilocksVariable, WIDTH)
	// for r := 0; r < WIDTH; r++ {
	// 	state[r] = inputs[r]
	// }

	// Compute inputs Sum
	sum := frontend.Variable(0)
	for i := 0; i < len(inputs); i++ {
		sum = api.Add(sum, inputs[i].Limb)
	}

	// Add sum + diag entry * element to each element
	for i := 0; i < WIDTH; i++ {
		matInternalDiag := api.Sub(MAT_DIAG12_M_1(i), 1)
		multiNoReduce := api.Add(api.Mul(matInternalDiag, inputs[i].Limb), sum)
		multi := goldilocks.Reduce(api, rangeChecker, multiNoReduce, 128) // sure 128?
		inputs[i] = multi
	}
}

func ConstantLayer(api frontend.API, rangeChecker frontend.Rangechecker, state []goldilocks.GoldilocksVariable, roundCtr int) {
	for i := 0; i < WIDTH; i++ {
		state[i] = goldilocks.Add(api, rangeChecker, state[i], goldilocks.GoldilocksVariable{Limb: RC12(roundCtr, i)})
	}
}

func SboxMonomial(api frontend.API, rangeChecker frontend.Rangechecker, x goldilocks.GoldilocksVariable) goldilocks.GoldilocksVariable {
	// x |--> x^7
	x2NoReduce := api.Mul(x.Limb, x.Limb)
	x3NoReduce := api.Mul(x.Limb, x2NoReduce)
	x3 := goldilocks.Reduce(api, rangeChecker, x3NoReduce, 192)
	x4NoReduce := api.Mul(x.Limb, x3.Limb)
	x7NoReduce := api.Mul(x3.Limb, x4NoReduce)
	x7 := goldilocks.Reduce(api, rangeChecker, x7NoReduce, 192)
	return x7
}

func SboxLayer(api frontend.API, rangeChecker frontend.Rangechecker, state []goldilocks.GoldilocksVariable) {
	for i := 0; i < WIDTH; i++ {
		if i < WIDTH {
			state[i] = SboxMonomial(api, rangeChecker, state[i])
		}
	}

}

func Poseidon2(api frontend.API, rangeChecker frontend.Rangechecker, currentState []goldilocks.GoldilocksVariable) {
	// M_E * X
	MatmulExternal(api, rangeChecker, currentState)

	// External_i, i in {0 - R_F/2 -1}
	for roundCtr := 0; roundCtr < ROUND_F_BEGIN; roundCtr++ {
		ConstantLayer(api, rangeChecker, currentState, roundCtr)
		SboxLayer(api, rangeChecker, currentState)
		MatmulExternal(api, rangeChecker, currentState)
	}

	// Internal_i
	for r := 0; r < ROUND_P; r++ {
		// TODO: optimization possible?

		// t_0 = x_0 + c_0^i
		currentState[0] = goldilocks.Add(api, rangeChecker, currentState[0], goldilocks.GoldilocksVariable{Limb: RC12_MID(r)})
		// t_1 = t_0^7
		currentState[0] = SboxMonomial(api, rangeChecker, currentState[0])
		// M_I * t_1
		MatmulInternal(api, rangeChecker, currentState)
	}

	// External_i, i in {R_F/2 = R/F - 1}
	for roundCtr := ROUND_F_BEGIN; roundCtr < ROUND_F_END; roundCtr++ {
		ConstantLayer(api, rangeChecker, currentState, roundCtr)
		SboxLayer(api, rangeChecker, currentState)
		MatmulExternal(api, rangeChecker, currentState)
	}
}

func (poseidon *Poseidon2Goldilocks) Permute(api frontend.API, rangeChecker frontend.Rangechecker, inputs []goldilocks.GoldilocksVariable) []goldilocks.GoldilocksVariable {
	if len(inputs) != WIDTH {
		panic("Invalid number of inputs")
	}

	// slice x
	currentState := make([]goldilocks.GoldilocksVariable, 12)
	for j := 0; j < WIDTH; j++ {
		currentState[j] = inputs[j]
	}
	Poseidon2(api, rangeChecker, currentState)
	return currentState
}
