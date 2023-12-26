package gates

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	algebra "github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks/extension"
	"github.com/consensys/gnark/frontend"
)

type ReducingGate struct {
	NumCoeffs int `json:"num_coeffs"`
}

const START_COEFFS = 3 * D

func NewReducingGate(id string) *ReducingGate {
	id = strings.TrimPrefix(id, "ReducingGate")
	id = strings.Replace(id, "num_coeffs", "\"num_coeffs\"", 1)

	var gate ReducingGate
	err := json.Unmarshal([]byte(id), &gate)
	if err != nil {
		panic(fmt.Sprintln("Invalid gate id: ", id, err))
	}
	return &gate
}

func (gate *ReducingGate) EvalUnfiltered(api frontend.API, rangeChecker frontend.Rangechecker, vars EvaluationVars) []goldilocks.GoldilocksExtension2Variable {
	alpha := GetLocalExtAlgebra(vars.LocalWires, gate.wiresAlpha())
	oldAcc := GetLocalExtAlgebra(vars.LocalWires, gate.wiresOldAcc())
	coeffs := GetLocalWiresFromRange(vars.LocalWires, gate.wiresCoeffs())
	accs := make([][D][D]frontend.Variable, gate.NumCoeffs)
	for i := 0; i < len(accs); i++ {
		accs[i] = GetLocalExtAlgebra(vars.LocalWires, gate.wiresAccs(i))
	}

	constraints := make([]goldilocks.GoldilocksExtension2Variable, gate.numConstraints())

	acc := oldAcc
	for i := 0; i < gate.NumCoeffs; i++ {
		constraintNoReduce := algebra.SubNoReduce(api, algebra.AddNoReduce(api, algebra.MulNoReduce(api, acc, alpha), algebra.FromBase(coeffs[i])), accs[i])
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

func (gate *ReducingGate) numConstraints() int {
	return D * gate.NumCoeffs
}

func (gate *ReducingGate) wiresAlpha() [2]int {
	return [2]int{D, 2 * D}
}

func (gate *ReducingGate) wiresOldAcc() [2]int {
	return [2]int{2 * D, 3 * D}
}

func (gate *ReducingGate) wiresCoeffs() [2]int {
	return [2]int{START_COEFFS, START_COEFFS + gate.NumCoeffs}
}

func (gate *ReducingGate) wiresOutput() [2]int {
	return [2]int{0, D}
}

func (gate *ReducingGate) startAccs() int {
	return START_COEFFS + gate.NumCoeffs
}

func (gate *ReducingGate) wiresAccs(i int) [2]int {
	if i == gate.NumCoeffs-1 {
		// The last accumulator is the output.
		return gate.wiresOutput()
	}
	return [2]int{gate.startAccs() + D*i, gate.startAccs() + D*(i+1)}
}
