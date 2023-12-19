package gates

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	algebra "github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks/extension"
	"github.com/consensys/gnark/frontend"
)

type ArithmeticExtensionGate struct {
	NumOps int `json:"num_ops"`
}

const D = goldilocks.D

func NewArithmeticExtensionGate(id string) *ArithmeticExtensionGate {
	id = strings.TrimPrefix(id, "ArithmeticExtensionGate")
	id = strings.Replace(id, "num_ops", "\"num_ops\"", 1)
	var gate ArithmeticExtensionGate
	err := json.Unmarshal([]byte(id), &gate)
	if err != nil {
		panic(fmt.Sprintln("Invalid gate id: ", id, err))
	}
	return &gate
}

func (gate *ArithmeticExtensionGate) EvalUnfiltered(api frontend.API, rangeChecker frontend.Rangechecker, vars EvaluationVars) []goldilocks.GoldilocksExtension2Variable {
	const0 := goldilocks.GetVariableArray(vars.LocalConstants[0])
	const1 := goldilocks.GetVariableArray(vars.LocalConstants[1])

	constraints := make([]goldilocks.GoldilocksExtension2Variable, gate.NumOps*D)
	for i := 0; i < gate.NumOps; i++ {
		// wires
		multiplicand0 := gate.LocalWires_ithMultiplicand0(vars.LocalWires, i)
		multiplicand1 := gate.LocalWires_ithMultiplicand1(vars.LocalWires, i)
		addend := gate.LocalWires_ithAddend(vars.LocalWires, i)
		output := gate.LocalWires_ithOutput(vars.LocalWires, i)

		computedOutputNoReduce := algebra.MulNoReduce(api, multiplicand0, multiplicand1)
		// (64 + 64 + 3) + 1
		// (132 + 64 + 3) + 1
		// ((132 + 64 + 3) + 1) + 1 = 201

		computedOutputNoReduce = algebra.ScalarMulNoReduce(api, computedOutputNoReduce, const0)
		// (201 + 64 + 3) + 1 = 269

		computedOutputNoReduce = algebra.AddNoReduce(api, computedOutputNoReduce, algebra.ScalarMulNoReduce(api, addend, const1))
		// (64 + 64 + 3) + 1
		// 269
		// 269 + 1 = 270

		// TODO: get bits for each of 4 numbers in computedOutputNoReduce (270 is the maximum among all)

		constraintNoReduce := [D][D]frontend.Variable{
			{api.Sub(computedOutputNoReduce[0][0], output[0][0]), api.Sub(computedOutputNoReduce[0][1], output[0][1])},
			{api.Sub(computedOutputNoReduce[1][0], output[1][0]), api.Sub(computedOutputNoReduce[1][1], output[1][1])},
		}

		constraints[i*D] = goldilocks.NegExt(api,
			goldilocks.GoldilocksExtension2Variable{
				A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0][0], 270),
				B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0][1], 270)},
		)

		constraints[i*D+1] = goldilocks.NegExt(api,
			goldilocks.GoldilocksExtension2Variable{
				A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1][0], 270),
				B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1][1], 270)},
		)
	}
	return constraints
}

func (gate *ArithmeticExtensionGate) LocalWires_ithMultiplicand0(wires []goldilocks.GoldilocksExtension2Variable, i int) [D][D]frontend.Variable {
	return GetVariableArray(wires[4*D*i : 4*D*i+D])
}

func (gate *ArithmeticExtensionGate) LocalWires_ithMultiplicand1(wires []goldilocks.GoldilocksExtension2Variable, i int) [D][D]frontend.Variable {
	return GetVariableArray(wires[4*D*i+D : 4*D*i+2*D])
}

func (gate *ArithmeticExtensionGate) LocalWires_ithAddend(wires []goldilocks.GoldilocksExtension2Variable, i int) [D][D]frontend.Variable {
	return GetVariableArray(wires[4*D*i+2*D : 4*D*i+3*D])
}

func (gate *ArithmeticExtensionGate) LocalWires_ithOutput(wires []goldilocks.GoldilocksExtension2Variable, i int) [D][D]frontend.Variable {
	return GetVariableArray(wires[4*D*i+3*D : 4*D*i+4*D])
}

func GetVariableArray(in []goldilocks.GoldilocksExtension2Variable) [D][D]frontend.Variable {
	if len(in) != D {
		panic("arithmetic extension::GetVariableArray - Invalid number of inputs")
	}
	out := [D][D]frontend.Variable{}
	for i, elm := range in {
		out[i] = goldilocks.GetVariableArray(elm)
	}
	return out
}
