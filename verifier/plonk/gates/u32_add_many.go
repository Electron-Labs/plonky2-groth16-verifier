package gates

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark/frontend"
)

type U32AddManyGate struct {
	NumAddends int `json:"num_addends"`
	NumOps     int `json:"num_ops"`
}

func NewU32AddManyGate(id string) *U32AddManyGate {
	splits := strings.Split(id, ", _phantom")
	if splits[1] != ": PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }" {
		panic(fmt.Sprintln("Invalid gate id: ", id))
	}
	id = splits[0]
	id = strings.Join([]string{id, "}"}, "")
	id = strings.TrimPrefix(id, "U32AddManyGate")
	id = strings.Replace(id, "num_addends", "\"num_addends\"", 1)
	id = strings.Replace(id, "num_ops", "\"num_ops\"", 1)

	var gate U32AddManyGate
	err := json.Unmarshal([]byte(id), &gate)
	if err != nil {
		panic(fmt.Sprintln("Invalid gate id: ", id, err))
	}
	return &gate
}

func (gate *U32AddManyGate) EvalUnfiltered(api frontend.API, rangeChecker frontend.Rangechecker, vars EvaluationVars) []goldilocks.GoldilocksExtension2Variable {
	idx := 0
	constraints := make([]goldilocks.GoldilocksExtension2Variable, gate.numConstraints())

	for i := 0; i < gate.NumOps; i++ {
		addends := make([]goldilocks.GoldilocksExtension2Variable, gate.NumAddends)
		for j := 0; j < gate.NumAddends; j++ {
			addends[j] = vars.LocalWires[gate.wire_ithOp_jthAddend(i, j)]
		}

		carry := vars.LocalWires[gate.wire_ithCarry(i)]

		computedOutput := goldilocks.BaseTo2Ext(goldilocks.GetGoldilocksVariable(0))
		for j := 0; j < len(addends); j++ {
			computedOutput = goldilocks.AddExt(api, rangeChecker, computedOutput, addends[j])
		}
		computedOutput = goldilocks.AddExt(api, rangeChecker, computedOutput, carry)

		outputResultRaw := goldilocks.GetVariableArray(vars.LocalWires[gate.wire_ithOutputResult(i)])
		outputCarryRaw := goldilocks.GetVariableArray(vars.LocalWires[gate.wire_ithOutputCarry(i)])

		base := goldilocks.BaseTo2ExtRaw(1 << 32)
		combinedOutputNoReduce := goldilocks.AddExtNoReduce(api, goldilocks.MulExtNoReduce(api, outputCarryRaw, base), outputResultRaw)
		constraintNoReduce := goldilocks.SubExtNoReduce(api, combinedOutputNoReduce, goldilocks.GetVariableArray(computedOutput))
		constraints[idx] = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0], 101),
			B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1], 99),
		}
		idx += 1

		combinedResultLimbs := goldilocks.BaseTo2ExtRaw(0)
		combinedCarryLimbs := goldilocks.BaseTo2ExtRaw(0)
		base = goldilocks.BaseTo2ExtRaw(1 << gate.limbBits())

		for j := gate.numLimbs() - 1; j >= 0; j-- {
			thisLimb := goldilocks.GetVariableArray(vars.LocalWires[gate.wire_ithOutput_jthLimb(i, j)])
			maxLimb := 1 << gate.limbBits()

			product := goldilocks.BaseTo2ExtRaw(1)
			for k := 0; k < maxLimb; k++ {
				productNoReduce := goldilocks.MulExtNoReduce(api, product, goldilocks.SubExtNoReduce(api, thisLimb, goldilocks.BaseTo2ExtRaw(k)))
				product = [D]frontend.Variable{
					goldilocks.Reduce(api, rangeChecker, productNoReduce[0], 132).Limb,
					goldilocks.Reduce(api, rangeChecker, productNoReduce[1], 130).Limb,
				}
			}
			constraints[idx] = goldilocks.GoldilocksExtension2Variable{
				A: goldilocks.GoldilocksVariable{Limb: product[0]},
				B: goldilocks.GoldilocksVariable{Limb: product[1]},
			}
			idx += 1

			var combinedResultLimbsNoReduce [D]frontend.Variable
			var combinedCarryLimbsNoReduce [D]frontend.Variable
			if j < gate.numResultLimbs() {
				combinedResultLimbsNoReduce = goldilocks.AddExtNoReduce(api, goldilocks.MulExtNoReduce(api, base, combinedResultLimbs), thisLimb)
				combinedResultLimbs = [D]frontend.Variable{
					goldilocks.Reduce(api, rangeChecker, combinedResultLimbsNoReduce[0], 70).Limb,
					goldilocks.Reduce(api, rangeChecker, combinedResultLimbsNoReduce[1], 67).Limb,
				}
			} else {
				combinedCarryLimbsNoReduce = goldilocks.AddExtNoReduce(api, goldilocks.MulExtNoReduce(api, base, combinedCarryLimbs), thisLimb)
				combinedCarryLimbs = [D]frontend.Variable{
					goldilocks.Reduce(api, rangeChecker, combinedCarryLimbsNoReduce[0], 70).Limb,
					goldilocks.Reduce(api, rangeChecker, combinedCarryLimbsNoReduce[1], 67).Limb,
				}
			}
		}

		constraintNoReduce = goldilocks.SubExtNoReduce(api, combinedResultLimbs, outputResultRaw)
		constraints[idx] = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0], 65),
			B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1], 65),
		}
		idx += 1

		constraintNoReduce = goldilocks.SubExtNoReduce(api, combinedCarryLimbs, outputCarryRaw)
		constraints[idx] = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0], 65),
			B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1], 65),
		}
		idx += 1
	}

	return constraints
}

func (gate *U32AddManyGate) log2MaxNumAddends() int {
	return 4
}

func (gate *U32AddManyGate) numResultLimbs() int {
	return (32 + gate.limbBits() - 1) / gate.limbBits()
}

func (gate *U32AddManyGate) numConstraints() int {
	return gate.NumOps * (3 + gate.numLimbs())
}

func (gate *U32AddManyGate) wire_ithOutput_jthLimb(i int, j int) int {
	return (gate.NumAddends+3)*gate.NumOps + gate.numLimbs()*i + j
}

func (gate *U32AddManyGate) wire_ithCarry(i int) int {
	return (gate.NumAddends+3)*i + gate.NumAddends
}

func (gate *U32AddManyGate) wire_ithOutputResult(i int) int {
	return (gate.NumAddends+3)*i + gate.NumAddends + 1
}
func (gate *U32AddManyGate) wire_ithOutputCarry(i int) int {
	return (gate.NumAddends+3)*i + gate.NumAddends + 2
}

func (gate *U32AddManyGate) wire_ithOp_jthAddend(i int, j int) int {
	return (gate.NumAddends+3)*i + j
}

func (gate *U32AddManyGate) limbBits() int {
	return 2
}

func (gate *U32AddManyGate) numCarryLimbs() int {
	return (gate.log2MaxNumAddends() + gate.limbBits() - 1) / gate.limbBits()
}

func (gate *U32AddManyGate) numLimbs() int {
	return gate.numResultLimbs() + gate.numCarryLimbs()
}
