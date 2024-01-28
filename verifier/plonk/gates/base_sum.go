package gates

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark/frontend"
)

type BaseSumGate struct {
	NumLimbs int `json:"num_limbs"`
	Base     int `json:"base"`
}

const WIRE_SUM = 0
const START_LIMBS = 1

func NewBaseSumGate(id string) *BaseSumGate {
	id = strings.TrimPrefix(id, "BaseSumGate")
	id = strings.Replace(id, " } +", ",", 1)
	id = strings.Join([]string{id, "}"}, "")
	id = strings.Replace(id, "num_limbs", "\"num_limbs\"", 1)
	id = strings.Replace(id, "Base", "\"base\"", 1)
	var gate BaseSumGate
	err := json.Unmarshal([]byte(id), &gate)
	if err != nil {
		panic(fmt.Sprintln("Invalid gate id: ", id, err))
	}
	return &gate
}

func (gate *BaseSumGate) EvalUnfiltered(api frontend.API, rangeChecker frontend.Rangechecker, vars EvaluationVars) []goldilocks.GoldilocksExtension2Variable {
	if gate.Base != 2 {
		panic(fmt.Sprintln("BaseSum gate::base must be 2"))
	}
	numLimbs := gate.NumLimbs
	constraints := make([]goldilocks.GoldilocksExtension2Variable, 1+numLimbs)

	sum := goldilocks.GetVariableArray(vars.LocalWires[WIRE_SUM])
	limbsRaw := GetLocalWiresFromRange(vars.LocalWires, limbs(numLimbs))
	limbs := make([]goldilocks.GoldilocksExtension2Variable, len(limbsRaw))
	for i := 0; i < len(limbs); i++ {
		limbs[i] = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.GoldilocksVariable{Limb: limbsRaw[i][0]},
			B: goldilocks.GoldilocksVariable{Limb: limbsRaw[i][1]},
		}
	}
	computedSum := goldilocks.GetVariableArray(ReduceWithPowers(api, rangeChecker, limbs, goldilocks.BaseTo2Ext(goldilocks.GoldilocksVariable{Limb: gate.Base})))
	constraintNoReduce := goldilocks.SubExtNoReduce(api, computedSum, sum)
	constraints[0] = goldilocks.GoldilocksExtension2Variable{
		A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0], 65),
		B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1], 65),
	}
	for i := 0; i < numLimbs; i++ {
		constraintNoReduce := limbsRaw[i]
		for j := 1; j < gate.Base; j++ {
			constraintNoReduce = goldilocks.MulExtNoReduce(api, constraintNoReduce, goldilocks.SubExtNoReduce(api, limbsRaw[i], goldilocks.BaseTo2ExtRaw(j)))
		}
		constraints[i+1] = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0], 132),
			B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1], 130),
		}
	}
	return constraints
}

// Returns the index of the `i`th limb wire.
func limbs(numLimbs int) [2]int {
	return [2]int{START_LIMBS, START_LIMBS + numLimbs}
}
