package gates

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark/frontend"
)

type U32SubtractionGate struct {
	NumOps int `json:"num_ops"`
}

func NewU32SubtractionGate(id string) *U32SubtractionGate {
	splits := strings.Split(id, ", _phantom")
	if splits[1] != ": PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }" {
		panic(fmt.Sprintln("Invalid gate id: ", id))
	}
	id = splits[0]
	id = strings.Join([]string{id, "}"}, "")
	id = strings.TrimPrefix(id, "U32SubtractionGate")
	id = strings.Replace(id, "num_ops", "\"num_ops\"", 1)

	var gate U32SubtractionGate
	err := json.Unmarshal([]byte(id), &gate)
	if err != nil {
		panic(fmt.Sprintln("Invalid gate id: ", id, err))
	}
	return &gate
}

func (gate *U32SubtractionGate) EvalUnfiltered(api frontend.API, rangeChecker frontend.Rangechecker, vars EvaluationVars) []goldilocks.GoldilocksExtension2Variable {
	var constraints []goldilocks.GoldilocksExtension2Variable
	for i := 0; i < gate.NumOps; i++ {
		inputX := goldilocks.GetVariableArray(vars.LocalWires[gate.wire_ithInputX(i)])
		inputY := goldilocks.GetVariableArray(vars.LocalWires[gate.wire_ithInputY(i)])
		inputBorrow := goldilocks.GetVariableArray(vars.LocalWires[gate.wire_ithInputBorrow(i)])

		resultInitial := goldilocks.SubExtNoReduce(api, goldilocks.SubExtNoReduce(api, inputX, inputY), inputBorrow)
		base := goldilocks.BaseTo2ExtRaw(1 << 32)

		outputResult := goldilocks.GetVariableArray(vars.LocalWires[gate.wire_ithOutputResult(i)])
		outputBorrow := goldilocks.GetVariableArray(vars.LocalWires[gate.wire_ithOutputBorrow(i)])

		constraintNoReduce := goldilocks.SubExtNoReduce(api, goldilocks.AddExtNoReduce(api, resultInitial, goldilocks.MulExtNoReduce(api, base, outputBorrow)), outputResult)
		constraints = append(constraints, goldilocks.NegExt(api,
			goldilocks.GoldilocksExtension2Variable{
				A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0], 98),
				B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1], 98)},
		))

		combinedLimbs := goldilocks.BaseTo2ExtRaw(0)
		limbBase := goldilocks.BaseTo2ExtRaw(1 << gate.limbBits())
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

			constraints = append(constraints, goldilocks.GoldilocksExtension2Variable{
				A: goldilocks.GoldilocksVariable{Limb: product[0]},
				B: goldilocks.GoldilocksVariable{Limb: product[1]},
			})

			combinedLimbsNoReduce := goldilocks.AddExtNoReduce(api, goldilocks.MulExtNoReduce(api, limbBase, combinedLimbs), thisLimb)
			combinedLimbs = [D]frontend.Variable{
				goldilocks.Reduce(api, rangeChecker, combinedLimbsNoReduce[0], 67).Limb,
				goldilocks.Reduce(api, rangeChecker, combinedLimbsNoReduce[1], 67).Limb,
			}
		}
		constraintNoReduce = goldilocks.SubExtNoReduce(api, combinedLimbs, outputResult)
		constraints = append(constraints, goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0], 65),
			B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1], 65),
		})

		constraintNoReduce = goldilocks.MulExtNoReduce(api, outputBorrow, goldilocks.SubExtNoReduce(api, goldilocks.BaseTo2ExtRaw(1), outputBorrow))
		constraints = append(constraints, goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0], 131),
			B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1], 129),
		})
	}
	return constraints
}

func (gate *U32SubtractionGate) numConstraints() int {
	return gate.NumOps * (3 + gate.numLimbs())
}

func (gate *U32SubtractionGate) wire_ithInputX(i int) int {
	return 5 * i
}

func (gate *U32SubtractionGate) wire_ithInputY(i int) int {
	return 5*i + 1
}
func (gate *U32SubtractionGate) wire_ithInputBorrow(i int) int {
	return 5*i + 2
}

func (gate *U32SubtractionGate) wire_ithOutputResult(i int) int {
	return 5*i + 3
}
func (gate *U32SubtractionGate) wire_ithOutputBorrow(i int) int {
	return 5*i + 4
}

func (gate *U32SubtractionGate) limbBits() int {
	return 2
}
func (gate *U32SubtractionGate) numLimbs() int {
	return 32 / gate.limbBits()
}

func (gate *U32SubtractionGate) wire_ithOutput_jthLimb(i int, j int) int {
	return 5*gate.NumOps + gate.numLimbs()*i + j
}
