package gates

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark/frontend"
)

type ConstantGate struct {
	NumConsts int `json:"num_consts"`
}

func NewConstantGate(id string) *ConstantGate {
	id = strings.TrimPrefix(id, "ConstantGate")
	id = strings.Replace(id, "num_consts", "\"num_consts\"", 1)
	var gate ConstantGate
	err := json.Unmarshal([]byte(id), &gate)
	if err != nil {
		panic(fmt.Sprintln("Invalid gate id: ", id, err))
	}
	return &gate
}

func (gate *ConstantGate) EvalUnfiltered(api frontend.API, rangeChecker frontend.Rangechecker, vars EvaluationVars) []goldilocks.GoldilocksExtension2Variable {
	constraints := make([]goldilocks.GoldilocksExtension2Variable, gate.NumConsts)

	for i := 0; i < gate.NumConsts; i++ {
		constraints[i] = goldilocks.SubExt(api, rangeChecker, vars.LocalConstants[gate.const_input(i)], vars.LocalWires[gate.wire_output(i)])
	}

	return constraints
}

func (gate *ConstantGate) const_input(i int) int {
	return i
}

func (gate *ConstantGate) wire_output(i int) int {
	return i
}
