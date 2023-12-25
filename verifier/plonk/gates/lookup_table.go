package gates

import (
	"encoding/json"
	"fmt"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark/frontend"
)

type LookupTableGate struct {
}

func NewLookupTableGate(id string) *LookupTableGate {
	var gate LookupTableGate
	err := json.Unmarshal([]byte("{}"), &gate)
	if err != nil {
		panic(fmt.Sprintln("Invalid gate id: ", id, err))
	}
	return &gate
}

func (gate *LookupTableGate) EvalUnfiltered(api frontend.API, rangeChecker frontend.Rangechecker, vars EvaluationVars) []goldilocks.GoldilocksExtension2Variable {
	constraints := make([]goldilocks.GoldilocksExtension2Variable, 0)

	return constraints
}
