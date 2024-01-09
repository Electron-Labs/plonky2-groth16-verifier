package gates

import (
	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	algebra "github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks/extension"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/types"
	"github.com/consensys/gnark/frontend"
)

type EvaluationVars struct {
	LocalConstants   []goldilocks.GoldilocksExtension2Variable
	LocalWires       []goldilocks.GoldilocksExtension2Variable
	PublicInputsHash types.HashOutVariable
}

func (vars *EvaluationVars) RemovePrefix(num_selectors int) {
	vars.LocalConstants = vars.LocalConstants[num_selectors:]
}

func GetLocalExtAlgebra(wires []goldilocks.GoldilocksExtension2Variable, range_ [2]int) [D][D]frontend.Variable {
	if range_[1]-range_[0] != D {
		panic("gate::GetLocalExtAlgebra - range must have `D` elements")
	}
	twoWires := [D]goldilocks.GoldilocksExtension2Variable{wires[range_[0]], wires[range_[1]-1]}
	return algebra.GetVariableArray(twoWires)
}
