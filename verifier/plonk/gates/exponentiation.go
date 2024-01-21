package gates

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark/frontend"
)

type ExponentiationGate struct {
	NumPowerBits int `json:"num_power_bits"`
}

func NewExponentiationGate(id string) *ExponentiationGate {
	splits := strings.Split(id, ", _phantom")
	if splits[1] != ": PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }" {
		panic(fmt.Sprintln("Invalid gate id: ", id))
	}
	id = splits[0]
	id = strings.Split(id, ", _phantom")[0]
	id = strings.Join([]string{id, "}"}, "")
	id = strings.TrimPrefix(id, "ExponentiationGate ")
	id = strings.Replace(id, "num_power_bits", "\"num_power_bits\"", 1)
	var gate ExponentiationGate
	err := json.Unmarshal([]byte(id), &gate)
	if err != nil {
		panic(fmt.Sprintln("Invalid gate id: ", id, err))
	}
	return &gate
}

func (gate *ExponentiationGate) EvalUnfiltered(api frontend.API, rangeChecker frontend.Rangechecker, vars EvaluationVars) []goldilocks.GoldilocksExtension2Variable {
	base := goldilocks.GetVariableArray(vars.LocalWires[gate.wireBase()])

	powerBits := make([][D]frontend.Variable, gate.NumPowerBits)
	for i := 0; i < len(powerBits); i++ {
		powerBits[i] = goldilocks.GetVariableArray(vars.LocalWires[gate.wirePowerBit(i)])
	}

	intermediateValues := make([][D]frontend.Variable, gate.NumPowerBits)
	for i := 0; i < len(powerBits); i++ {
		intermediateValues[i] = goldilocks.GetVariableArray(vars.LocalWires[gate.wireIntermediateValue(i)])
	}

	output := vars.LocalWires[gate.wireOutput()]

	constraints := make([]goldilocks.GoldilocksExtension2Variable, gate.numConstraints())

	for i := 0; i < gate.NumPowerBits; i++ {
		var prevIntermediateValueNoReduce [D]frontend.Variable
		var prevIntermediateValue goldilocks.GoldilocksExtension2Variable
		if i == 0 {
			prevIntermediateValue = goldilocks.BaseTo2Ext(goldilocks.GoldilocksVariable{Limb: 1})
		} else {
			prevIntermediateValueNoReduce = goldilocks.MulExtNoReduce(api, intermediateValues[i-1], intermediateValues[i-1])
			prevIntermediateValue = goldilocks.GoldilocksExtension2Variable{
				A: goldilocks.Reduce(api, rangeChecker, prevIntermediateValueNoReduce[0], 131),
				B: goldilocks.Reduce(api, rangeChecker, prevIntermediateValueNoReduce[1], 129),
			}
		}

		prevIntermediateValueRaw := [D]frontend.Variable{prevIntermediateValue.A.Limb, prevIntermediateValue.B.Limb}

		// power_bits is in LE order, but we accumulate in BE order.
		curBit := powerBits[gate.NumPowerBits-i-1]
		notCurBit := goldilocks.SubExtNoReduce(api, goldilocks.BaseTo2ExtRaw(1), curBit)
		computedIntermediateValue := goldilocks.MulExtNoReduce(
			api,
			prevIntermediateValueRaw,
			goldilocks.AddExtNoReduce(
				api,
				goldilocks.MulExtNoReduce(api, curBit, base),
				notCurBit,
			),
		)
		constraintNoReduce := goldilocks.SubExtNoReduce(api, computedIntermediateValue, intermediateValues[i])
		constraints[i] = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0], 199),
			B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1], 198),
		}
	}

	constraints[gate.NumPowerBits] = goldilocks.SubExt(
		api,
		rangeChecker,
		output,
		goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.GoldilocksVariable{Limb: intermediateValues[gate.NumPowerBits-1][0]},
			B: goldilocks.GoldilocksVariable{Limb: intermediateValues[gate.NumPowerBits-1][1]},
		},
	)
	return constraints
}

func (gate *ExponentiationGate) wireBase() int {
	return 0
}

// The `i`th bit of the exponent, in little-endian order.
func (gate *ExponentiationGate) wirePowerBit(i int) int {
	return 1 + i
}

func (gate *ExponentiationGate) wireOutput() int {
	return 1 + gate.NumPowerBits
}

func (gate *ExponentiationGate) wireIntermediateValue(i int) int {
	return 2 + gate.NumPowerBits + i
}

func (gate ExponentiationGate) numConstraints() int {
	return gate.NumPowerBits + 1
}
