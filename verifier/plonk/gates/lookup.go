package gates

import (
	"fmt"
	"strings"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark/frontend"
)

type LookupGate struct {
}

func NewLookupGate(id string) *LookupGate {
	if strings.HasPrefix(id, "LookupGate") != true {
		panic(fmt.Sprintln("Invalid gate id: ", id))
	}

	return new(LookupGate)
}

func (gate *LookupGate) EvalUnfiltered(api frontend.API, rangeChecker frontend.Rangechecker, vars EvaluationVars) []goldilocks.GoldilocksExtension2Variable {
	constraints := make([]goldilocks.GoldilocksExtension2Variable, 0)

	return constraints
}
