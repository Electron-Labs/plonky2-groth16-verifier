package gates

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark/frontend"
)

type U32ArithmeticGate struct {
	NumOps int `json:"num_ops"`
}

func NewU32ArithmeticGate(id string) *U32ArithmeticGate {
	splits := strings.Split(id, ", _phantom")
	if splits[1] != ": PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }" {
		panic(fmt.Sprintln("Invalid gate id: ", id))
	}
	id = splits[0]
	id = strings.Join([]string{id, "}"}, "")
	id = strings.TrimPrefix(id, "U32ArithmeticGate")
	id = strings.Replace(id, "num_ops", "\"num_ops\"", 1)

	var gate U32ArithmeticGate
	err := json.Unmarshal([]byte(id), &gate)
	if err != nil {
		panic(fmt.Sprintln("Invalid gate id: ", id, err))
	}
	return &gate
}

func (gate *U32ArithmeticGate) EvalUnfiltered(api frontend.API, rangeChecker frontend.Rangechecker, vars EvaluationVars) []goldilocks.GoldilocksExtension2Variable {
	idx := 0
	constraints := make([]goldilocks.GoldilocksExtension2Variable, gate.numConstraints())

	for i := 0; i < gate.NumOps; i++ {
		multiplicand0Raw := goldilocks.GetVariableArray(vars.LocalWires[gate.wire_ithMultiplicand0(i)])
		multiplicand1Raw := goldilocks.GetVariableArray(vars.LocalWires[gate.wire_ithMultiplicand1(i)])
		addendRaw := goldilocks.GetVariableArray(vars.LocalWires[gate.wire_ithAddend(i)])

		computedOutputNoReduce := goldilocks.AddExtNoReduce(api, goldilocks.MulExtNoReduce(api, multiplicand0Raw, multiplicand1Raw), addendRaw)
		computedOutput := [D]frontend.Variable{
			goldilocks.Reduce(api, rangeChecker, computedOutputNoReduce[0], 132).Limb,
			goldilocks.Reduce(api, rangeChecker, computedOutputNoReduce[1], 130).Limb,
		}

		outputLowRaw := goldilocks.GetVariableArray(vars.LocalWires[gate.wire_ithOutputLowHalf(i)])
		outputHighRaw := goldilocks.GetVariableArray(vars.LocalWires[gate.wire_ithOutputHighHalf(i)])
		inverseRaw := goldilocks.GetVariableArray(vars.LocalWires[gate.wire_ithInverse(i)])

		// Check canonicity of combined_output = output_high * 2^32 + output_low
		base := goldilocks.BaseTo2ExtRaw(1 << 32)
		one := goldilocks.BaseTo2ExtRaw(1)
		u32Max := goldilocks.BaseTo2ExtRaw(math.MaxUint32)

		// This is zero if and only if the high limb is `u32::MAX`.
		// u32::MAX - output_high
		diffNoReduce := goldilocks.SubExtNoReduce(api, u32Max, outputHighRaw)
		// If this is zero, the diff is invertible, so the high limb is not `u32::MAX`.
		// inverse * diff - 1
		hiNotMaxNoReduce := goldilocks.SubExtNoReduce(api, goldilocks.MulExtNoReduce(api, inverseRaw, diffNoReduce), one)
		// If this is zero, either the high limb is not `u32::MAX`, or the low limb is zero.
		// hi_not_max * limb_0_u32
		hiNotMaxOrLoZeroNoReduce := goldilocks.MulExtNoReduce(api, hiNotMaxNoReduce, outputLowRaw)
		constraints[idx] = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, hiNotMaxOrLoZeroNoReduce[0], 201),
			B: goldilocks.Reduce(api, rangeChecker, hiNotMaxOrLoZeroNoReduce[1], 198),
		}
		idx += 1

		combinedOutputNoReduce := goldilocks.AddExtNoReduce(api, goldilocks.MulExtNoReduce(api, outputHighRaw, base), outputLowRaw)

		constraintNoReduce := goldilocks.SubExtNoReduce(api, combinedOutputNoReduce, computedOutput)
		constraints[idx] = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0], 100),
			B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1], 97),
		}
		idx += 1

		combinedLowLimbs := goldilocks.BaseTo2ExtRaw(0)
		combinedHighLimbs := goldilocks.BaseTo2ExtRaw(0)
		midpoint := gate.numLimbs() / 2
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

			var combinedLowLimbsNoReduce [D]frontend.Variable
			var combinedHighLimbsNoReduce [D]frontend.Variable
			if j < midpoint {
				combinedLowLimbsNoReduce = goldilocks.AddExtNoReduce(api, goldilocks.MulExtNoReduce(api, base, combinedLowLimbs), thisLimb)
				combinedLowLimbs = [D]frontend.Variable{
					goldilocks.Reduce(api, rangeChecker, combinedLowLimbsNoReduce[0], 70).Limb,
					goldilocks.Reduce(api, rangeChecker, combinedLowLimbsNoReduce[1], 67).Limb,
				}
			} else {
				combinedHighLimbsNoReduce = goldilocks.AddExtNoReduce(api, goldilocks.MulExtNoReduce(api, base, combinedHighLimbs), thisLimb)
				combinedHighLimbs = [D]frontend.Variable{
					goldilocks.Reduce(api, rangeChecker, combinedHighLimbsNoReduce[0], 70).Limb,
					goldilocks.Reduce(api, rangeChecker, combinedHighLimbsNoReduce[1], 67).Limb,
				}
			}
		}

		constraintNoReduce = goldilocks.SubExtNoReduce(api, combinedLowLimbs, outputLowRaw)
		constraints[idx] = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0], 65),
			B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1], 65),
		}
		idx += 1

		constraintNoReduce = goldilocks.SubExtNoReduce(api, combinedHighLimbs, outputHighRaw)
		constraints[idx] = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0], 65),
			B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1], 65),
		}
		idx += 1
	}

	return constraints
}

func (gate *U32ArithmeticGate) numConstraints() int {
	return gate.NumOps * (4 + gate.numLimbs())
}

func (gate *U32ArithmeticGate) numLimbs() int {
	return 64 / gate.limbBits()
}

func (gate *U32ArithmeticGate) limbBits() int {
	return 2
}

func (gate *U32ArithmeticGate) routedWiresPerOp() int {
	return 6
}

func (gate *U32ArithmeticGate) wire_ithMultiplicand0(i int) int {
	return gate.routedWiresPerOp() * i
}
func (gate *U32ArithmeticGate) wire_ithMultiplicand1(i int) int {
	return gate.routedWiresPerOp()*i + 1
}
func (gate *U32ArithmeticGate) wire_ithAddend(i int) int {
	return gate.routedWiresPerOp()*i + 2
}

func (gate *U32ArithmeticGate) wire_ithOutputLowHalf(i int) int {
	return gate.routedWiresPerOp()*i + 3
}

func (gate *U32ArithmeticGate) wire_ithOutputHighHalf(i int) int {
	return gate.routedWiresPerOp()*i + 4
}

func (gate *U32ArithmeticGate) wire_ithInverse(i int) int {
	return gate.routedWiresPerOp()*i + 5
}

func (gate *U32ArithmeticGate) wire_ithOutput_jthLimb(i int, j int) int {
	return gate.routedWiresPerOp()*gate.NumOps + gate.numLimbs()*i + j
}
