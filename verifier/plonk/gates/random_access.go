package gates

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark/frontend"
)

type RandomAccessGate struct {
	Bits              int `json:"bits"`
	NumCopies         int `json:"num_copies"`
	NumExtraConstants int `json:"num_extra_constants"`
}

func NewRandomAccessGate(id string) *RandomAccessGate {
	id = strings.Split(id, ", _phantom")[0]
	id = strings.Join([]string{id, "}"}, "")
	id = strings.TrimPrefix(id, "RandomAccessGate")
	id = strings.Replace(id, "bits", "\"bits\"", 1)
	id = strings.Replace(id, "num_copies", "\"num_copies\"", 1)
	id = strings.Replace(id, "num_extra_constants", "\"num_extra_constants\"", 1)

	var gate RandomAccessGate
	err := json.Unmarshal([]byte(id), &gate)
	if err != nil {
		panic(fmt.Sprintln("Invalid gate id: ", id, err))
	}
	return &gate
}

func (gate *RandomAccessGate) EvalUnfiltered(api frontend.API, rangeChecker frontend.Rangechecker, vars EvaluationVars) []goldilocks.GoldilocksExtension2Variable {
	constraints := make([]goldilocks.GoldilocksExtension2Variable, gate.numConstraints())
	nConstraintsPerCopy := gate.Bits + 2

	for copy := 0; copy < gate.NumCopies; copy++ {
		accessIndex := goldilocks.GetVariableArray(vars.LocalWires[gate.wireAccessIndex(copy)])
		listItems := make([][D]frontend.Variable, gate.vecSize())
		for i := 0; i < len(listItems); i++ {
			listItems[i] = goldilocks.GetVariableArray(vars.LocalWires[gate.wireListItem(i, copy)])
		}
		claimedElement := vars.LocalWires[gate.wireClaimedElement(copy)]
		bits := make([][D]frontend.Variable, gate.Bits)
		for i := 0; i < len(bits); i++ {
			bits[i] = goldilocks.GetVariableArray(vars.LocalWires[gate.wireBit(i, copy)])
		}

		// Assert that each bit wire value is indeed boolean.
		for i := 0; i < len(bits); i++ {
			constraintNoReduce := goldilocks.MulExtNoReduce(api, bits[i], goldilocks.SubExtNoReduce(api, bits[i], goldilocks.BaseTo2ExtRaw(1)))
			constraints[copy*nConstraintsPerCopy+i] = goldilocks.GoldilocksExtension2Variable{
				A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0], 132),
				B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1], 129),
			}
		}

		// Assert that the binary decomposition was correct.
		reconstructedIndex := goldilocks.BaseTo2ExtRaw(0)
		for i := len(bits) - 1; i >= 0; i-- {
			reconstructedIndex = goldilocks.AddExtNoReduce(api, goldilocks.AddExtNoReduce(api, reconstructedIndex, reconstructedIndex), bits[i])
		}
		constraintNoReduce := goldilocks.SubExtNoReduce(api, reconstructedIndex, accessIndex)
		constraints[copy*nConstraintsPerCopy+gate.Bits] = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0], 70),
			B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1], 70),
		}

		// Repeatedly fold the list, selecting the left or right item from each pair based on
		// the corresponding bit.
		for i := 0; i < len(bits); i++ {
			listItemsFolded := make([][D]frontend.Variable, len(listItems)/2)
			for j := 0; j < len(listItemsFolded); j++ {
				subItem := goldilocks.GetVariableArray(
					goldilocks.SubExt(api, rangeChecker,
						goldilocks.GoldilocksExtension2Variable{
							A: goldilocks.GoldilocksVariable{Limb: listItems[2*j+1][0]},
							B: goldilocks.GoldilocksVariable{Limb: listItems[2*j+1][1]},
						},
						goldilocks.GoldilocksExtension2Variable{
							A: goldilocks.GoldilocksVariable{Limb: listItems[2*j][0]},
							B: goldilocks.GoldilocksVariable{Limb: listItems[2*j][1]},
						},
					))

				item := goldilocks.AddExtNoReduce(api, listItems[2*j], goldilocks.MulExtNoReduce(api, bits[i], subItem))
				listItemsFolded[j] = [2]frontend.Variable{
					goldilocks.Reduce(api, rangeChecker, item[0], 133).Limb,
					goldilocks.Reduce(api, rangeChecker, item[1], 130).Limb,
				}
			}
			listItems = listItemsFolded
		}

		constraints[copy*nConstraintsPerCopy+gate.Bits+1] = goldilocks.SubExt(api, rangeChecker,
			goldilocks.GoldilocksExtension2Variable{
				A: goldilocks.GoldilocksVariable{Limb: listItems[0][0]},
				B: goldilocks.GoldilocksVariable{Limb: listItems[0][1]},
			},
			claimedElement,
		)
	}

	for i := 0; i < gate.NumExtraConstants; i++ {
		constraints[gate.NumCopies*(nConstraintsPerCopy)+i] = goldilocks.SubExt(api, rangeChecker, vars.LocalConstants[i],
			vars.LocalWires[gate.wireExtraConstant(i)],
		)
	}

	return constraints
}

func (gate *RandomAccessGate) numConstraints() int {
	constraintsPerCopy := gate.Bits + 2
	return gate.NumCopies*constraintsPerCopy + gate.NumExtraConstants
}

// Length of the list being accessed.
func (gate *RandomAccessGate) vecSize() int {
	return 1 << gate.Bits
}

// For each copy, a wire containing the claimed index of the element.
func (gate *RandomAccessGate) wireAccessIndex(copy int) int {
	return (2 + gate.vecSize()) * copy
}

// For each copy, wires containing the entire list.
func (gate *RandomAccessGate) wireListItem(i int, copy int) int {
	return (2+gate.vecSize())*copy + 2 + i
}

// / For each copy, a wire containing the element claimed to be at the index.
func (gate *RandomAccessGate) wireClaimedElement(copy int) int {
	return (2+gate.vecSize())*copy + 1
}

func (gate *RandomAccessGate) startExtraConstants() int {
	return (2 + gate.vecSize()) * gate.NumCopies
}

// / All above wires are routed.
func (gate *RandomAccessGate) numRoutedWires() int {
	return gate.startExtraConstants() + gate.NumExtraConstants
}

// An intermediate wire where the prover gives the (purported) binary decomposition of the
// index.
func (gate *RandomAccessGate) wireBit(i int, copy int) int {
	return gate.numRoutedWires() + copy*gate.Bits + i
}

func (gate *RandomAccessGate) wireExtraConstant(i int) int {
	return gate.startExtraConstants() + i
}
