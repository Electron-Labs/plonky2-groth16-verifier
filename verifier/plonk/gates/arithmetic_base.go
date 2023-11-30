package gates

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark/frontend"
)

type ArithmeticGate struct {
	NumOps int `json:"num_ops"`
}

func NewArithmeticGate(id string) *ArithmeticGate {
	id = strings.TrimPrefix(id, "ArithmeticGate")
	id = strings.Replace(id, "num_ops", "\"num_ops\"", 1)
	var gate ArithmeticGate
	err := json.Unmarshal([]byte(id), &gate)
	if err != nil {
		panic(fmt.Sprintln("Invalid gate id: ", id, err))
	}
	return &gate
}

func (gate *ArithmeticGate) EvalUnfiltered(api frontend.API, rangeChecker frontend.Rangechecker, vars EvaluationVars) []goldilocks.GoldilocksExtension2Variable {
	const_0 := vars.LocalConstants[0]
	const_1 := vars.LocalConstants[1]

	constraints := make([]goldilocks.GoldilocksExtension2Variable, gate.NumOps)
	for i := 0; i < gate.NumOps; i++ {
		multiplicand_0 := vars.LocalWires[gate.wire_ith_multiplicand_0(i)]
		multiplicand_1 := vars.LocalWires[gate.wire_ith_multiplicand_1(i)]
		addend := vars.LocalWires[gate.wire_ith_addend(i)]
		output := vars.LocalWires[gate.wire_ith_output(i)]
		// computed_output := multiplicand_0*multiplicand_1*const_0 + addend*const_1
		co_multiplicand := goldilocks.MulExtNoReduce(
			api,
			goldilocks.GetVariableArray(multiplicand_0),
			goldilocks.GetVariableArray(multiplicand_1),
		)
		co_multiplicand = goldilocks.MulExtNoReduce(
			api,
			co_multiplicand,
			goldilocks.GetVariableArray(const_0),
		)
		co_addend := goldilocks.MulExtNoReduce(
			api,
			goldilocks.GetVariableArray(addend),
			goldilocks.GetVariableArray(const_1),
		)
		co_no_reduce := [2]frontend.Variable{api.Add(co_multiplicand[0], co_addend[0]), api.Add(co_multiplicand[1], co_addend[1])}
		constraints_i_no_reduce := [2]frontend.Variable{
			api.Add(api.Sub(co_no_reduce[0], output.A.Limb), goldilocks.MODULUS),
			api.Add(api.Sub(co_no_reduce[1], output.B.Limb), goldilocks.MODULUS),
		}
		constraints[i] = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, constraints_i_no_reduce[0], 197),
			B: goldilocks.Reduce(api, rangeChecker, constraints_i_no_reduce[1], 196),
		}
		constraints[i] = goldilocks.NegExt(api, constraints[i])
	}

	return constraints
}

func (gate *ArithmeticGate) wire_ith_multiplicand_0(i int) int {
	return 4 * i
}

func (gate *ArithmeticGate) wire_ith_multiplicand_1(i int) int {
	return 4*i + 1
}

func (gate *ArithmeticGate) wire_ith_addend(i int) int {
	return 4*i + 2
}

func (gate *ArithmeticGate) wire_ith_output(i int) int {
	return 4*i + 3
}
