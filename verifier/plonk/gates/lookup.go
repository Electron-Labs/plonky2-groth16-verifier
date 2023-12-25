package gates

import (
	"encoding/json"
	"fmt"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark/frontend"
)

type LookupGate struct {
}

func NewLookupGate(id string) *LookupGate {
	var gate LookupGate
	err := json.Unmarshal([]byte("{}"), &gate)
	if err != nil {
		panic(fmt.Sprintln("Invalid gate id: ", id, err))
	}
	return &gate
}

func (gate *LookupGate) EvalUnfiltered(api frontend.API, rangeChecker frontend.Rangechecker, vars EvaluationVars) []goldilocks.GoldilocksExtension2Variable {
	constraints := make([]goldilocks.GoldilocksExtension2Variable, 0)

	return constraints
}
