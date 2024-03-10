package gates

import (
	"fmt"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/types"
	"github.com/consensys/gnark/frontend"
)

type PublicInputGate struct{}

func NewPublicInputGate(id string) *PublicInputGate {
	if id != "PublicInputGate" {
		panic(fmt.Sprintln("Invalid gate id: ", id))
	}
	return new(PublicInputGate)
}

func (gate *PublicInputGate) EvalUnfiltered(api frontend.API, rangeChecker frontend.Rangechecker, vars EvaluationVars) []goldilocks.GoldilocksExtension2Variable {
	constraints := make([]goldilocks.GoldilocksExtension2Variable, types.POSEIDON_GOLDILOCKS_HASH_OUT)

	for i := 0; i < types.POSEIDON_GOLDILOCKS_HASH_OUT; i++ {
		constraints[i] = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Sub(api, rangeChecker, vars.LocalWires[i].A, vars.PublicInputsHash.HashOut[i]),
			B: vars.LocalWires[i].B,
		}
	}

	return constraints
}
