package gates

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark/frontend"
)

type U32InterleaveGate struct {
	NumOps int `json:"num_ops"`
}

func NewU32InterleaveGate(id string) *U32InterleaveGate {
	id = strings.TrimPrefix(id, "U32InterleaveGate")
	id = strings.Replace(id, "num_ops", "\"num_ops\"", 1)

	var gate U32InterleaveGate
	err := json.Unmarshal([]byte(id), &gate)
	if err != nil {
		panic(fmt.Sprintln("Invalid gate id: ", id, err))
	}
	return &gate
}

func (gate *U32InterleaveGate) EvalUnfiltered(api frontend.API, rangeChecker frontend.Rangechecker, vars EvaluationVars) []goldilocks.GoldilocksExtension2Variable {
	var constraints []goldilocks.GoldilocksExtension2Variable

	for i := 0; i < gate.NumOps; i++ {
		x := goldilocks.GetVariableArray(vars.LocalWires[gate.wire_ithX(i)])
		bitsRaw := GetLocalWiresFromRange(vars.LocalWires, gate.wires_ithBitDecomposition(i))
		bits := make([]goldilocks.GoldilocksExtension2Variable, len(bitsRaw))
		for i := 0; i < len(bits); i++ {
			bits[i] = goldilocks.GoldilocksExtension2Variable{
				A: goldilocks.GoldilocksVariable{Limb: bitsRaw[i][0]},
				B: goldilocks.GoldilocksVariable{Limb: bitsRaw[i][1]},
			}
		}
		bitsRev := make([]goldilocks.GoldilocksExtension2Variable, len(bits))
		copy(bitsRev, bits)
		slices.Reverse(bitsRev)

		computedX := goldilocks.GetVariableArray(ReduceWithPowers(api, rangeChecker, bitsRev, goldilocks.BaseTo2Ext(goldilocks.GoldilocksVariable{Limb: 2})))

		constraintNoReduce := goldilocks.SubExtNoReduce(api, computedX, x)
		constraints = append(constraints, goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0], 65),
			B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1], 65),
		})

		xInterleaved := goldilocks.GetVariableArray(vars.LocalWires[gate.wire_ithXInterleaved(i)])

		computedXInterleaved := goldilocks.GetVariableArray(ReduceWithPowers(api, rangeChecker,
			bitsRev,
			goldilocks.BaseTo2Ext(goldilocks.GoldilocksVariable{Limb: 2 * 2})))
		constraintNoReduce = goldilocks.SubExtNoReduce(api, computedXInterleaved, xInterleaved)
		constraints = append(constraints, goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0], 65),
			B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1], 65),
		})

		for j := 0; j < len(bits); j++ {
			constraintNoReduce := bitsRaw[j]
			constraintNoReduce = goldilocks.MulExtNoReduce(api, constraintNoReduce, goldilocks.SubExtNoReduce(api, bitsRaw[j], goldilocks.BaseTo2ExtRaw(1)))
			constraints = append(constraints, goldilocks.GoldilocksExtension2Variable{
				A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0], 132),
				B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1], 130),
			})
		}
	}
	return constraints
}

func (gate *U32InterleaveGate) NUM_BITS() int {
	return 32
}

func (gate *U32InterleaveGate) wire_ithX(i int) int {
	return gate.routedWiresPerOp() * i
}

func (gate *U32InterleaveGate) routedWiresPerOp() int {
	return 2
}

func (gate *U32InterleaveGate) wires_ithBitDecomposition(i int) [2]int {
	start := gate.NumOps * gate.routedWiresPerOp()
	return [2]int{(start + gate.NUM_BITS()*i), (start + gate.NUM_BITS()*(i+1))}
}

func (gate *U32InterleaveGate) wire_ithXInterleaved(i int) int {
	return gate.routedWiresPerOp()*i + 1
}
