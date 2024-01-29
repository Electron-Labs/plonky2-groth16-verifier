package gates

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark/frontend"
)

type UninterleaveToU32Gate struct {
	NumOps int `json:"num_ops"`
}

func NewUninterleaveToU32Gate(id string) *UninterleaveToU32Gate {
	id = strings.TrimPrefix(id, "UninterleaveToU32Gate")
	id = strings.Replace(id, "num_ops", "\"num_ops\"", 1)

	var gate UninterleaveToU32Gate
	err := json.Unmarshal([]byte(id), &gate)
	if err != nil {
		panic(fmt.Sprintln("Invalid gate id: ", id, err))
	}
	return &gate
}

func (gate *UninterleaveToU32Gate) EvalUnfiltered(api frontend.API, rangeChecker frontend.Rangechecker, vars EvaluationVars) []goldilocks.GoldilocksExtension2Variable {
	var constraints []goldilocks.GoldilocksExtension2Variable

	for i := 0; i < gate.NumOps; i++ {
		x_interleaved := goldilocks.GetVariableArray(vars.LocalWires[gate.wire_ithXInterleaved(i)])
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

		computedXInterleaved := goldilocks.GetVariableArray(ReduceWithPowers(api, rangeChecker, bitsRev, goldilocks.BaseTo2Ext(goldilocks.GoldilocksVariable{Limb: 2})))

		constraintNoReduce := goldilocks.SubExtNoReduce(api, computedXInterleaved, x_interleaved)
		constraints = append(constraints, goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0], 65),
			B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1], 65),
		})

		xEvens := goldilocks.GetVariableArray(vars.LocalWires[gate.wire_ithXEvens(i)])
		xOdds := goldilocks.GetVariableArray(vars.LocalWires[gate.wire_ithXOdds(i)])

		computedXEvensNoReduce := goldilocks.BaseTo2ExtRaw(0)
		computedXOddsNoReduce := goldilocks.BaseTo2ExtRaw(0)

		// NUM_BITS = 32
		for j := 0; j < gate.NUM_BITS()/2; j++ {
			jthEven := bitsRaw[2*j]
			jthOdd := bitsRaw[2*j+1]

			coeff := goldilocks.BaseTo2ExtRaw(1 << (gate.NUM_BITS()/2 - j - 1))
			computedXEvensNoReduce = goldilocks.AddExtNoReduce(api, computedXEvensNoReduce, goldilocks.MulExtNoReduce(api, coeff, jthEven))
			computedXOddsNoReduce = goldilocks.AddExtNoReduce(api, computedXOddsNoReduce, goldilocks.MulExtNoReduce(api, coeff, jthOdd))
		}

		constraintNoReduce = goldilocks.SubExtNoReduce(api, computedXEvensNoReduce, xEvens)
		constraints = append(constraints, goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0], 127),
			B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1], 127),
		})

		constraintNoReduce = goldilocks.SubExtNoReduce(api, computedXOddsNoReduce, xOdds)
		constraints = append(constraints, goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0], 127),
			B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1], 127),
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

func (gate *UninterleaveToU32Gate) routedWiresPerOp() int {
	return 3
}

func (gate *UninterleaveToU32Gate) wire_ithXInterleaved(i int) int {
	return gate.routedWiresPerOp() * i
}

func (gate *UninterleaveToU32Gate) NUM_BITS() int {
	return 64
}

func (gate *UninterleaveToU32Gate) wires_ithBitDecomposition(i int) [2]int {
	start := gate.NumOps * gate.routedWiresPerOp()
	return [2]int{start + gate.NUM_BITS()*i, start + gate.NUM_BITS()*(i+1)}
}

func (gate *UninterleaveToU32Gate) wire_ithXEvens(i int) int {
	return gate.routedWiresPerOp()*i + 1
}

func (gate *UninterleaveToU32Gate) wire_ithXOdds(i int) int {
	return gate.routedWiresPerOp()*i + 2
}
