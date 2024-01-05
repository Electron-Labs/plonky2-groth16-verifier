package gates

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	algebra "github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks/extension"
	"github.com/consensys/gnark/frontend"
)

type MulExtensionGate struct {
	NumOps int `json:"num_ops"`
}

func NewMulExtensionGate(id string) *MulExtensionGate {
	id = strings.TrimPrefix(id, "MulExtensionGate")
	id = strings.Replace(id, "num_ops", "\"num_ops\"", 1)
	var gate MulExtensionGate
	err := json.Unmarshal([]byte(id), &gate)
	if err != nil {
		panic(fmt.Sprintln("Invalid gate id: ", id, err))
	}
	return &gate
}

func (gate *MulExtensionGate) EvalUnfiltered(api frontend.API, rangeChecker frontend.Rangechecker, vars EvaluationVars) []goldilocks.GoldilocksExtension2Variable {
	const0 := goldilocks.GetVariableArray(vars.LocalConstants[0])
	constraints := make([]goldilocks.GoldilocksExtension2Variable, gate.NumOps*D)

	for i := 0; i < gate.NumOps; i++ {
		multiplicand0 := GetLocalExtAlgebra(vars.LocalWires, gate.wires_ithMultiplicand0(i))
		multiplicand1 := GetLocalExtAlgebra(vars.LocalWires, gate.wires_ithMultiplicand1(i))
		output := GetLocalExtAlgebra(vars.LocalWires, gate.wires_ithOutput(i))
		computedOutputNoReduce := algebra.ScalarMulNoReduce(api, algebra.MulNoReduce(api, multiplicand0, multiplicand1), const0)
		// assumming computedOutputNoReduce is always greator than output
		constraintNoReduce := [D][D]frontend.Variable{
			{api.Sub(computedOutputNoReduce[0][0], output[0][0]), api.Sub(computedOutputNoReduce[0][1], output[0][1])},
			{api.Sub(computedOutputNoReduce[1][0], output[1][0]), api.Sub(computedOutputNoReduce[1][1], output[1][1])},
		}

		constraints[i*D] = goldilocks.NegExt(api,
			goldilocks.GoldilocksExtension2Variable{
				A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0][0], 201),
				B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0][1], 201)},
		)

		constraints[i*D+1] = goldilocks.NegExt(api,
			goldilocks.GoldilocksExtension2Variable{
				A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1][0], 198),
				B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1][1], 198)},
		)
	}
	return constraints
}

func (gate *MulExtensionGate) wires_ithMultiplicand0(i int) [2]int {
	return [2]int{3 * D * i, 3*D*i + D}
}
func (gate *MulExtensionGate) wires_ithMultiplicand1(i int) [2]int {
	return [2]int{3*D*i + D, 3*D*i + 2*D}
}
func (gate *MulExtensionGate) wires_ithOutput(i int) [2]int {
	return [2]int{3*D*i + 2*D, 3*D*i + 3*D}
}
