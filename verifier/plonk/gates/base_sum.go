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
	numLimbs := gate.NumLimbs
	constraints := make([]goldilocks.GoldilocksExtension2Variable, 1+numLimbs)

	sum := goldilocks.GetVariableArray(vars.LocalWires[WIRE_SUM])
	limbs := GetLocalWiresFromRange(vars.LocalWires, limbs(numLimbs))
	computedSumNoReduce := reduceWithPowers(api, rangeChecker, limbs, goldilocks.BaseTo2ExtRaw(gate.Base)) // 188 bits max for tendermint circuits (Base = 2)
	// assumuing computedSumNoReduce is always > sum
	constraintNoReduce := goldilocks.SubExtNoReduce(api, computedSumNoReduce, sum)
	constraints[0] = goldilocks.GoldilocksExtension2Variable{
		A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0], 188),
		B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1], 188),
	}
	for i := 0; i < numLimbs; i++ {
		constraintNoReduce := goldilocks.SubExtNoReduce(api, limbs[i], goldilocks.BaseTo2ExtRaw(0))
		for j := 1; j < gate.Base; j++ {
			constraintNoReduce = goldilocks.MulExtNoReduce(api, constraintNoReduce, goldilocks.SubExtNoReduce(api, limbs[i], goldilocks.BaseTo2ExtRaw(j)))
		}
		constraints[i+1] = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0], 132),
			B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1], 129),
		}
	}
	return constraints
}

func reduceWithPowers(api frontend.API, rangeChecker frontend.Rangechecker, terms [][D]frontend.Variable, alpha [D]frontend.Variable) [D]frontend.Variable {
	sumNoReduce := goldilocks.ZERO()
	nTerms := len(terms)
	for i := 0; i < nTerms; i++ {
		sumNoReduce = goldilocks.AddExtNoReduce(api, goldilocks.MulExtNoReduce(api, sumNoReduce, alpha), terms[nTerms-1-i])
	}

	return sumNoReduce
}

// Returns the index of the `i`th limb wire.
func limbs(numLimbs int) [2]int {
	return [2]int{START_LIMBS, START_LIMBS + numLimbs}
}
