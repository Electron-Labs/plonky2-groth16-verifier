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
		multiplicand0 := GetLocalExtAlgebra(vars.LocalWires, gate.Wires_ithMultiplicand0(i))
		multiplicand1 := GetLocalExtAlgebra(vars.LocalWires, gate.Wires_ithMultiplicand1(i))
		addend := GetLocalExtAlgebra(vars.LocalWires, gate.Wires_ithAddend(i))
		output := GetLocalExtAlgebra(vars.LocalWires, gate.Wires_ithOutput(i))

		computedOutputNoReduce := algebra.MulNoReduce(api, multiplicand0, multiplicand1)
		computedOutputNoReduce = algebra.ScalarMulNoReduce(api, computedOutputNoReduce, const0)
		computedOutputNoReduce = algebra.AddNoReduce(api, computedOutputNoReduce, algebra.ScalarMulNoReduce(api, addend, const1))
		// assumming computedOutputNoReduce is always greator than output
		constraintNoReduce := [D][D]frontend.Variable{
			{api.Sub(computedOutputNoReduce[0][0], output[0][0]), api.Sub(computedOutputNoReduce[0][1], output[0][1])},
			{api.Sub(computedOutputNoReduce[1][0], output[1][0]), api.Sub(computedOutputNoReduce[1][1], output[1][1])},
		}

		constraints[i*D] = goldilocks.NegExt(api,
			goldilocks.GoldilocksExtension2Variable{
				A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0][0], 199),
				B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0][1], 199)},
		)

		constraints[i*D+1] = goldilocks.NegExt(api,
			goldilocks.GoldilocksExtension2Variable{
				A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1][0], 205),
				B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1][1], 203)},
		)
	}
	return constraints
}

func (gate *ArithmeticExtensionGate) Wires_ithMultiplicand0(i int) [2]int {
	return [2]int{4 * D * i, 4*D*i + D}
}

func (gate *ArithmeticExtensionGate) Wires_ithMultiplicand1(i int) [2]int {
	return [2]int{4*D*i + D, 4*D*i + 2*D}
}

func (gate *ArithmeticExtensionGate) Wires_ithAddend(i int) [2]int {
	return [2]int{4*D*i + 2*D, 4*D*i + 3*D}
}

func (gate *ArithmeticExtensionGate) Wires_ithOutput(i int) [2]int {
	return [2]int{4*D*i + 3*D, 4*D*i + 4*D}
}
