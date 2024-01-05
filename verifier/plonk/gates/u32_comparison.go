package gates

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark/frontend"
)

type U32ComparisonGate struct {
	NumBits   int `json:"num_bits"`
	NumChunks int `json:"num_chunks"`
}

func NewU32ComparisonGate(id string) *U32ComparisonGate {
	splits := strings.Split(id, ", _phantom")
	if splits[1] != ": PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>" {
		panic(fmt.Sprintln("Invalid gate id: ", id))
	}
	id = splits[0]
	id = strings.Join([]string{id, "}"}, "")
	id = strings.TrimPrefix(id, "ComparisonGate")
	id = strings.Replace(id, "num_bits", "\"num_bits\"", 1)
	id = strings.Replace(id, "num_chunks", "\"num_chunks\"", 1)

	var gate U32ComparisonGate
	err := json.Unmarshal([]byte(id), &gate)
	if err != nil {
		panic(fmt.Sprintln("Invalid gate id: ", id, err))
	}
	return &gate
}

func (gate *U32ComparisonGate) EvalUnfiltered(api frontend.API, rangeChecker frontend.Rangechecker, vars EvaluationVars) []goldilocks.GoldilocksExtension2Variable {
	idx := 0
	constraints := make([]goldilocks.GoldilocksExtension2Variable, gate.numConstraints())
	firstInput := vars.LocalWires[gate.wireFirstInput()]
	secondInput := vars.LocalWires[gate.wireSecondInput()]

	// Get chunks and assert that they match
	firstChunks := make([]goldilocks.GoldilocksExtension2Variable, gate.NumChunks)
	firstChunksRaw := make([][D]frontend.Variable, gate.NumChunks)
	for i := 0; i < gate.NumChunks; i++ {
		firstChunks[i] = vars.LocalWires[gate.wireFirstChunkVal(i)]
		firstChunksRaw[i] = goldilocks.GetVariableArray(vars.LocalWires[gate.wireFirstChunkVal(i)])
	}

	secondChunks := make([]goldilocks.GoldilocksExtension2Variable, gate.NumChunks)
	secondChunksRaw := make([][D]frontend.Variable, gate.NumChunks)
	for i := 0; i < gate.NumChunks; i++ {
		secondChunks[i] = vars.LocalWires[gate.wireSecondChunkVal(i)]
		secondChunksRaw[i] = goldilocks.GetVariableArray(vars.LocalWires[gate.wireSecondChunkVal(i)])
	}
	firstChunksCombined := ReduceWithPowers(api, rangeChecker, firstChunks, goldilocks.BaseTo2Ext(goldilocks.GoldilocksVariable{Limb: 1 << gate.chunkBits()}))
	secondChunksCombined := ReduceWithPowers(api, rangeChecker, secondChunks, goldilocks.BaseTo2Ext(goldilocks.GoldilocksVariable{Limb: 1 << gate.chunkBits()}))

	constraints[idx] = goldilocks.SubExt(api, rangeChecker, firstChunksCombined, firstInput)
	idx += 1
	constraints[idx] = goldilocks.SubExt(api, rangeChecker, secondChunksCombined, secondInput)
	idx += 1

	chunkSize := 1 << gate.chunkBits()

	mostSignificantDiffSoFar := goldilocks.ZERO()

	for i := 0; i < gate.NumChunks; i++ {
		// Range-check the chunks to be less than `chunk_size`.
		firstProduct := goldilocks.BaseTo2ExtRaw(1)
		secondProduct := goldilocks.BaseTo2ExtRaw(1)

		// assuming `chunkSize` is in the goldilocks range
		// TODO: optimize here?
		for j := 0; j < chunkSize; j++ {
			firstSubNoReduce := goldilocks.SubExtNoReduce(api, firstChunksRaw[i], goldilocks.BaseTo2ExtRaw(j))
			firstProductNoReduce := goldilocks.MulExtNoReduce(api, firstProduct, firstSubNoReduce)
			firstProduct = [2]frontend.Variable{goldilocks.Reduce(api, rangeChecker, firstProductNoReduce[0], 132).Limb,
				goldilocks.Reduce(api, rangeChecker, firstProductNoReduce[1], 130).Limb}

			secondSubNoReduce := goldilocks.SubExtNoReduce(api, secondChunksRaw[i], goldilocks.BaseTo2ExtRaw(j))
			secondProductNoReduce := goldilocks.MulExtNoReduce(api, secondProduct, secondSubNoReduce)
			secondProduct = [2]frontend.Variable{goldilocks.Reduce(api, rangeChecker, secondProductNoReduce[0], 132).Limb,
				goldilocks.Reduce(api, rangeChecker, secondProductNoReduce[1], 130).Limb}
		}

		constraints[idx] = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.GoldilocksVariable{Limb: firstProduct[0]},
			B: goldilocks.GoldilocksVariable{Limb: firstProduct[1]},
		}
		idx += 1
		constraints[idx] = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.GoldilocksVariable{Limb: secondProduct[0]},
			B: goldilocks.GoldilocksVariable{Limb: secondProduct[1]},
		}
		idx += 1

		differenceNoReduce := goldilocks.SubExtNoReduce(api, secondChunksRaw[i], firstChunksRaw[i])
		equalityDummy := goldilocks.GetVariableArray(vars.LocalWires[gate.wireEqualityDummy(i)])
		chunksEqual := vars.LocalWires[gate.wireChunksEqual(i)]
		chunksEqualRaw := goldilocks.GetVariableArray(vars.LocalWires[gate.wireChunksEqual(i)])

		// Two constraints to assert that `chunks_equal` is valid.
		aNoReduce := goldilocks.MulExtNoReduce(api, differenceNoReduce, equalityDummy)
		bNoReduce := goldilocks.SubExtNoReduce(api, goldilocks.BaseTo2ExtRaw(1), chunksEqualRaw)
		constraintNoReduce := goldilocks.SubExtNoReduce(api, aNoReduce, bNoReduce)
		constraints[idx] = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0], 132),
			B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1], 130),
		}
		idx += 1

		constraints[idx] = goldilocks.MulExt(api, rangeChecker, chunksEqual, goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, differenceNoReduce[0], 65),
			B: goldilocks.Reduce(api, rangeChecker, differenceNoReduce[1], 65),
		})
		idx += 1

		// Update `most_significant_diff_so_far`.
		intermediateValue := goldilocks.GetVariableArray(vars.LocalWires[gate.wireIntermediateValue(i)])
		constraintNoReduce = goldilocks.SubExtNoReduce(api, goldilocks.MulExtNoReduce(api, chunksEqualRaw, mostSignificantDiffSoFar), intermediateValue)
		constraints[idx] = goldilocks.NegExt(api,
			goldilocks.GoldilocksExtension2Variable{
				A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0], 132),
				B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1], 130)},
		)
		idx += 1

		mostSignificantDiffSoFarNoReduce := goldilocks.AddExtNoReduce(api, intermediateValue, goldilocks.MulExtNoReduce(api, goldilocks.SubExtNoReduce(api, goldilocks.BaseTo2ExtRaw(1), chunksEqualRaw), differenceNoReduce))
		mostSignificantDiffSoFar = [2]frontend.Variable{
			goldilocks.Reduce(api, rangeChecker, mostSignificantDiffSoFarNoReduce[0], 133).Limb,
			goldilocks.Reduce(api, rangeChecker, mostSignificantDiffSoFarNoReduce[1], 131).Limb,
		}
	}

	mostSignificantDiff := goldilocks.GetVariableArray(vars.LocalWires[gate.wireMostSignificantDiff()])
	constraintNoReduce := goldilocks.SubExtNoReduce(api, mostSignificantDiff, mostSignificantDiffSoFar)
	constraints[idx] = goldilocks.GoldilocksExtension2Variable{
		A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0], 65),
		B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1], 65),
	}
	idx += 1

	mostSignificantDiffBits := make([]goldilocks.GoldilocksExtension2Variable, gate.chunkBits()+1)
	mostSignificantDiffBitsRaw := make([][D]frontend.Variable, gate.chunkBits()+1)
	for i := 0; i < gate.chunkBits()+1; i++ {
		mostSignificantDiffBits[i] = vars.LocalWires[gate.wireMostSignificantDiffBit(i)]
		mostSignificantDiffBitsRaw[i] = goldilocks.GetVariableArray(vars.LocalWires[gate.wireMostSignificantDiffBit(i)])
	}

	// Range-check the bits.
	for i := 0; i < len(mostSignificantDiffBits); i++ {
		bitNoReduce := mostSignificantDiffBitsRaw[i]
		constraintNoReduce := goldilocks.MulExtNoReduce(api, bitNoReduce, goldilocks.SubExtNoReduce(api, goldilocks.BaseTo2ExtRaw(1), bitNoReduce))
		constraints[idx] = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0], 131),
			B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1], 129),
		}
		idx += 1
	}

	bitsCombined := goldilocks.GetVariableArray(ReduceWithPowers(api, rangeChecker, mostSignificantDiffBits, goldilocks.BaseTo2Ext(goldilocks.GoldilocksVariable{Limb: 2})))
	twoN := goldilocks.BaseTo2ExtRaw(1 << gate.chunkBits())
	// assuming `twoN` is in goldilocks range
	constraintNoReduce = goldilocks.SubExtNoReduce(api, goldilocks.AddExtNoReduce(api, twoN, mostSignificantDiff), bitsCombined)
	constraints[idx] = goldilocks.GoldilocksExtension2Variable{
		A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0], 66),
		B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1], 66),
	}
	idx += 1

	// Iff first <= second, the top (n + 1st) bit of (2^n + most_significant_diff) will be 1.
	resultBool := vars.LocalWires[gate.wireResultBool()]
	constraints[idx] = goldilocks.SubExt(api, rangeChecker, resultBool, mostSignificantDiffBits[gate.chunkBits()])
	idx += 1

	return constraints
}

func (gate *U32ComparisonGate) numConstraints() int {
	return 6 + 5*gate.NumChunks + gate.chunkBits()
}

func (gate *U32ComparisonGate) wireResultBool() int {
	return 2
}

// The `bit_index`th bit of 2^n - 1 + most_significant_diff.
func (gate *U32ComparisonGate) wireMostSignificantDiffBit(bitIndex int) int {
	return 4 + 5*gate.NumChunks + bitIndex
}

func (gate *U32ComparisonGate) wireMostSignificantDiff() int {
	return 3
}

func (gate *U32ComparisonGate) wireIntermediateValue(chunk int) int {
	return 4 + 4*gate.NumChunks + chunk
}

func (gate *U32ComparisonGate) wireEqualityDummy(chunk int) int {
	return 4 + 2*gate.NumChunks + chunk
}

func (gate *U32ComparisonGate) wireChunksEqual(chunk int) int {
	return 4 + 3*gate.NumChunks + chunk
}

func (gate *U32ComparisonGate) wireFirstChunkVal(chunk int) int {
	return 4 + chunk
}

func (gate *U32ComparisonGate) wireSecondChunkVal(chunk int) int {
	return 4 + gate.NumChunks + chunk
}

func (gate *U32ComparisonGate) chunkBits() int {
	return (gate.NumBits + gate.NumChunks - 1) / gate.NumChunks
}

func (gate *U32ComparisonGate) wireFirstInput() int {
	return 0
}

func (gate *U32ComparisonGate) wireSecondInput() int {
	return 1
}
