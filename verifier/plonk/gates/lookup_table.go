package gates

import (
	"fmt"
	"strings"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark/frontend"
)

type LookupTableGate struct {
}

func NewLookupTableGate(id string) *LookupTableGate {
	if strings.HasPrefix(id, "LookupTableGate") != true {
		panic(fmt.Sprintln("Invalid gate id: ", id))
	}

	return new(LookupTableGate)
}

func (gate *LookupTableGate) EvalUnfiltered(api frontend.API, rangeChecker frontend.Rangechecker, vars EvaluationVars) []goldilocks.GoldilocksExtension2Variable {
	constraints := make([]goldilocks.GoldilocksExtension2Variable, 0)

	return constraints
}
