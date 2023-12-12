package gates

import (
	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/types"
)

type EvaluationVars struct {
	LocalConstants   []goldilocks.GoldilocksExtension2Variable
	LocalWires       []goldilocks.GoldilocksExtension2Variable
	PublicInputsHash types.HashOutVariable
}

func (vars *EvaluationVars) RemovePrefix(num_selectors int) {
	vars.LocalConstants = vars.LocalConstants[num_selectors:]
}
