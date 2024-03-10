package gates

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	algebra "github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks/extension"
	"github.com/consensys/gnark/frontend"
)

type ReducingExtensionGate struct {
	NumCoeffs int `json:"num_coeffs"`
}

func NewReducingExtensionGate(id string) *ReducingExtensionGate {
	id = strings.TrimPrefix(id, "ReducingExtensionGate")
	id = strings.Replace(id, "num_coeffs", "\"num_coeffs\"", 1)

	var gate ReducingExtensionGate
	err := json.Unmarshal([]byte(id), &gate)
	if err != nil {
		panic(fmt.Sprintln("Invalid gate id: ", id, err))
	}
	return &gate
}

func (gate *ReducingExtensionGate) EvalUnfiltered(api frontend.API, rangeChecker frontend.Rangechecker, vars EvaluationVars) []goldilocks.GoldilocksExtension2Variable {
	alpha := GetLocalExtAlgebra(vars.LocalWires, gate.wiresAlpha())
	oldAcc := GetLocalExtAlgebra(vars.LocalWires, gate.wiresOldAcc())
	coeffs := make([][D][D]frontend.Variable, gate.NumCoeffs)
	for i := 0; i < gate.NumCoeffs; i++ {
		coeffs[i] = GetLocalExtAlgebra(vars.LocalWires, gate.wiresCoeff(i))
	}
	accs := make([][D][D]frontend.Variable, gate.NumCoeffs)
	for i := 0; i < gate.NumCoeffs; i++ {
		accs[i] = GetLocalExtAlgebra(vars.LocalWires, gate.wiresAccs(i))
	}

	constraints := make([]goldilocks.GoldilocksExtension2Variable, gate.numConstraints())

	acc := oldAcc
	for i := 0; i < gate.NumCoeffs; i++ {
		constraintNoReduce := algebra.SubNoReduce(api, algebra.AddNoReduce(api, algebra.MulNoReduce(api, acc, alpha), coeffs[i]), accs[i])
		constraints[2*i] = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0][0], 137),
			B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0][1], 134),
		}
		constraints[2*i+1] = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1][0], 134),
			B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1][1], 131),
		}
		acc = accs[i]
	}

	return constraints
}

func (gate *ReducingExtensionGate) numConstraints() int {
	return D * gate.NumCoeffs
}

func (gate *ReducingExtensionGate) wiresAlpha() [2]int {
	return [2]int{D, 2 * D}
}
func (gate *ReducingExtensionGate) wiresOldAcc() [2]int {
	return [2]int{2 * D, 3 * D}
}

func (gate *ReducingExtensionGate) wiresCoeff(i int) [2]int {
	return [2]int{gate.startCoeffs() + i*D, gate.startCoeffs() + (i+1)*D}
}

func (gate *ReducingExtensionGate) startCoeffs() int {
	return 3 * D
}

func (gate *ReducingExtensionGate) wiresOutput() [2]int {
	return [2]int{0, D}
}

func (gate *ReducingExtensionGate) startAccs() int {
	return gate.startCoeffs() + gate.NumCoeffs*D
}

func (gate *ReducingExtensionGate) wiresAccs(i int) [2]int {
	if i == gate.NumCoeffs-1 {
		// The last accumulator is the output.
		return gate.wiresOutput()
	}
	return [2]int{gate.startAccs() + D*i, gate.startAccs() + D*(i+1)}
}
