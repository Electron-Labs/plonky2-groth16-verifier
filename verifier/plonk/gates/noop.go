package gates

import (
	"fmt"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark/frontend"
)

type NoopGate struct {
}

func NewNoopGate(id string) *NoopGate {
	if id != "NoopGate" {
		panic(fmt.Sprintln("Invalid gate id: ", id))
	}
	return new(NoopGate)
}

func (gate *NoopGate) EvalUnfiltered(api frontend.API, rangeChecker frontend.Rangechecker, vars EvaluationVars) []goldilocks.GoldilocksExtension2Variable {
	constraints := make([]goldilocks.GoldilocksExtension2Variable, 0)

	return constraints
}
