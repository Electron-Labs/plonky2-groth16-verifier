package gates

// TODO: movie goldilocks_extension to quadratic

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	algebra "github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks/extension"
	"github.com/consensys/gnark/frontend"
)

type CosetInterpolationGate struct {
	SubgroupBits       int      `json:"subgroup_bits"`
	BarycentricWeights []uint64 `json:"barycentric_weights"`
	Degree             int      `json:"degree"`
}

func NewCosetInterpolationGate(id string) *CosetInterpolationGate {
	id = strings.Split(id, ", _phantom")[0]
	id = strings.Join([]string{id, "}"}, "")
	id = strings.TrimPrefix(id, "CosetInterpolationGate")
	id = strings.Replace(id, "subgroup_bits", "\"subgroup_bits\"", 1)
	id = strings.Replace(id, "barycentric_weights", "\"barycentric_weights\"", 1)
	id = strings.Replace(id, "degree", "\"degree\"", 1)

	var gate CosetInterpolationGate
	err := json.Unmarshal([]byte(id), &gate)
	if err != nil {
		panic(fmt.Sprintln("Invalid gate id: ", id, err))
	}
	return &gate
}

func (gate *CosetInterpolationGate) EvalUnfiltered(api frontend.API, rangeChecker frontend.Rangechecker, vars EvaluationVars) []goldilocks.GoldilocksExtension2Variable {
	subgroupBits := gate.SubgroupBits
	degree := gate.Degree
	numConstraints := NumConstraints(subgroupBits, degree)
	numPoints := NumPoints(subgroupBits)

	constraints := make([]goldilocks.GoldilocksExtension2Variable, numConstraints)

	shift := goldilocks.GetVariableArray(vars.LocalWires[WireShift()])
	evaluationPoint := GetLocalExtAlgebra(vars.LocalWires, WiresEvaluationPoint(subgroupBits))
	shiftedEvaluationPoint := GetLocalExtAlgebra(vars.LocalWires, WiresShiftedEvaluationPoint(subgroupBits, degree))

	a := algebra.ScalarMulNoReduce(api, shiftedEvaluationPoint, shift)

	// assuming a is always greator then evaluationPoint
	evalPointConstraint := [D][D]frontend.Variable{
		{api.Sub(a[0][0], evaluationPoint[0][0]), api.Sub(a[0][1], evaluationPoint[0][1])},
		{api.Sub(a[1][0], evaluationPoint[1][0]), api.Sub(a[1][1], evaluationPoint[1][1])},
	}
	constraints[0] = goldilocks.NegExt(api,
		goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, evalPointConstraint[0][0], 132),
			B: goldilocks.Reduce(api, rangeChecker, evalPointConstraint[0][1], 129)},
	)
	constraints[1] = goldilocks.NegExt(api,
		goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, evalPointConstraint[1][0], 132),
			B: goldilocks.Reduce(api, rangeChecker, evalPointConstraint[1][1], 129)},
	)

	domain := goldilocks.TwoAdicSubgroup(api, rangeChecker, subgroupBits)
	values := make([][2][2]frontend.Variable, numPoints)
	for i := 0; i < numPoints; i++ {
		values[i] = GetLocalExtAlgebra(vars.LocalWires, WiresValue(i))
	}

	weights := make([]frontend.Variable, len(gate.BarycentricWeights))
	for i := 0; i < len(weights); i++ {
		weights[i] = frontend.Variable(gate.BarycentricWeights[i])
	}

	computedEval, computedProd := PartialInterpolateExtAlgebra(
		api,
		rangeChecker,
		domain[:degree],
		values[:degree],
		weights[:degree],
		shiftedEvaluationPoint,
		algebra.ZERO(),
		algebra.FromBase(goldilocks.BaseTo2ExtRaw(1)),
	)

	numIntermediates := NumIntermediates(subgroupBits, degree)
	for i := 0; i < numIntermediates; i++ {
		intermediateEval := GetLocalExtAlgebra(vars.LocalWires, WiresIntermediateEval(subgroupBits, i))
		intermediateProd := GetLocalExtAlgebra(vars.LocalWires, WiresIntermediateProd(subgroupBits, degree, i))

		// set constraints on the following successive indices
		// D + i * 2 * D
		// D + i * 2 * D + 1
		// D + i * 2 * D + 2
		// D + i * 2 * D + 3
		constraints[D+i*2*D] = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Sub(api, rangeChecker, goldilocks.GetGoldilocks(intermediateEval[0][0]), goldilocks.GetGoldilocks(computedEval[0][0])),
			B: goldilocks.Sub(api, rangeChecker, goldilocks.GetGoldilocks(intermediateEval[0][1]), goldilocks.GetGoldilocks(computedEval[0][1])),
		}
		constraints[D+i*2*D+1] = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Sub(api, rangeChecker, goldilocks.GetGoldilocks(intermediateEval[1][0]), goldilocks.GetGoldilocks(computedEval[1][0])),
			B: goldilocks.Sub(api, rangeChecker, goldilocks.GetGoldilocks(intermediateEval[1][1]), goldilocks.GetGoldilocks(computedEval[1][1])),
		}
		constraints[D+i*2*D+2] = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Sub(api, rangeChecker, goldilocks.GetGoldilocks(intermediateProd[0][0]), goldilocks.GetGoldilocks(computedProd[0][0])),
			B: goldilocks.Sub(api, rangeChecker, goldilocks.GetGoldilocks(intermediateProd[0][1]), goldilocks.GetGoldilocks(computedProd[0][1])),
		}
		constraints[D+i*2*D+3] = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Sub(api, rangeChecker, goldilocks.GetGoldilocks(intermediateProd[1][0]), goldilocks.GetGoldilocks(computedProd[1][0])),
			B: goldilocks.Sub(api, rangeChecker, goldilocks.GetGoldilocks(intermediateProd[1][1]), goldilocks.GetGoldilocks(computedProd[1][1])),
		}

		startIndex := 1 + (degree-1)*(i+1)
		endIndex := min(startIndex+degree-1, numPoints)

		computedEval, computedProd = PartialInterpolateExtAlgebra(
			api,
			rangeChecker,
			domain[startIndex:endIndex],
			values[startIndex:endIndex],
			weights[startIndex:endIndex],
			shiftedEvaluationPoint,
			intermediateEval,
			intermediateProd,
		)
	}

	evaluationValue := GetLocalExtAlgebra(vars.LocalWires, WiresEvaluationValue(subgroupBits))

	constraints[numConstraints-2] = goldilocks.GoldilocksExtension2Variable{
		A: goldilocks.Sub(api, rangeChecker, goldilocks.GetGoldilocks(evaluationValue[0][0]), goldilocks.GetGoldilocks(computedEval[0][0])),
		B: goldilocks.Sub(api, rangeChecker, goldilocks.GetGoldilocks(evaluationValue[0][1]), goldilocks.GetGoldilocks(computedEval[0][1])),
	}
	constraints[numConstraints-1] = goldilocks.GoldilocksExtension2Variable{
		A: goldilocks.Sub(api, rangeChecker, goldilocks.GetGoldilocks(evaluationValue[1][0]), goldilocks.GetGoldilocks(computedEval[1][0])),
		B: goldilocks.Sub(api, rangeChecker, goldilocks.GetGoldilocks(evaluationValue[1][1]), goldilocks.GetGoldilocks(computedEval[1][1])),
	}

	return constraints
}

func PartialInterpolateExtAlgebra(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	domain []goldilocks.GoldilocksVariable,
	values [][D][D]frontend.Variable,
	barycentricWeights []frontend.Variable,
	x [D][D]frontend.Variable,
	initialEval [D][D]frontend.Variable,
	initialPartialProd [D][D]frontend.Variable,
) ([D][D]frontend.Variable, [D][D]frontend.Variable) {
	n := len(domain)
	if n == 0 {
		panic("domain length can't be 0")
	}
	if n != len(values) {
		panic("n != values")
	}
	if n != len(barycentricWeights) {
		panic("n != barycentricWeights")
	}

	weightedValues := make([][2][2]frontend.Variable, n)
	for i := 0; i < n; i++ {
		weightedValues[i] = algebra.ScalarMulNoReduce(api, values[i], goldilocks.BaseTo2ExtRaw(barycentricWeights[i]))
	}

	// accumulator variables
	eval, termsPartialProd := initialEval, initialPartialProd

	for i := 0; i < n; i++ {
		val := weightedValues[i]
		xi := domain[i].Limb
		term := algebra.Sub(api, rangeChecker, x, algebra.FromBase(goldilocks.BaseTo2ExtRaw(xi)))
		evalNoReduce := algebra.AddNoReduce(api, algebra.MulNoReduce(api, eval, term), algebra.MulNoReduce(api, val, termsPartialProd))
		termsPartialProdNoReduce := algebra.MulNoReduce(api, termsPartialProd, term)

		// TODO: verify reduce bits once more
		eval = [D][D]frontend.Variable{
			{goldilocks.Reduce(api, rangeChecker, evalNoReduce[0][0], 203).Limb, goldilocks.Reduce(api, rangeChecker, evalNoReduce[0][1], 200).Limb},
			{goldilocks.Reduce(api, rangeChecker, evalNoReduce[1][0], 199).Limb, goldilocks.Reduce(api, rangeChecker, evalNoReduce[1][1], 196).Limb},
		}
		termsPartialProd = [D][D]frontend.Variable{
			{goldilocks.Reduce(api, rangeChecker, termsPartialProdNoReduce[0][0], 133).Limb, goldilocks.Reduce(api, rangeChecker, termsPartialProdNoReduce[0][1], 133).Limb},
			{goldilocks.Reduce(api, rangeChecker, termsPartialProdNoReduce[1][0], 137).Limb, goldilocks.Reduce(api, rangeChecker, termsPartialProdNoReduce[1][1], 134).Limb},
		}
	}

	return eval, termsPartialProd
}

func NumConstraints(subgroupBits int, degree int) int {
	// D constraints to check for consistency of the shifted evaluation point, plus D
	// constraints for the evaluation value.
	return D + D + 2*D*NumIntermediates(subgroupBits, degree)
}

func NumPoints(subgroupBits int) int {
	return 1 << subgroupBits
}

// Wire index of the coset shift.
func WireShift() int {
	return 0
}

func StartValues() int {
	return 1
}

// Wire indices of the `i`th interpolant value.
func WiresValue(i int) [2]int {
	start := StartValues() + i*D
	return [2]int{start, start + D}
}

func StartEvaluationPoint(subgroupBits int) int {
	return StartValues() + NumPoints(subgroupBits)*D
}

// Wire indices of the point to evaluate the interpolant at.
func WiresEvaluationPoint(subgroupBits int) [2]int {
	start := StartEvaluationPoint(subgroupBits)
	return [2]int{start, start + D}
}

func NumIntermediates(subgroupBits int, degree int) int {
	return (NumPoints(subgroupBits) - 2) / (degree - 1)
}

// The wires corresponding to the i'th intermediate evaluation.
func WiresIntermediateEval(subgroupBits int, i int) [2]int {
	start := StartIntermediates(subgroupBits) + D*i
	return [2]int{start, start + D}
}

// The wires corresponding to the i'th intermediate product.
func WiresIntermediateProd(subgroupBits int, degree int, i int) [2]int {
	start := StartIntermediates(subgroupBits) + D*(NumIntermediates(subgroupBits, degree)+i)
	return [2]int{start, start + D}
}

func StartEvaluationValue(subgroupBits int) int {
	return StartEvaluationPoint(subgroupBits) + D
}

// Wire indices of the interpolated value.
func WiresEvaluationValue(subgroupBits int) [2]int {
	start := StartEvaluationValue(subgroupBits)
	return [2]int{start, start + D}
}

func StartIntermediates(subgroupBits int) int {
	return StartEvaluationValue(subgroupBits) + D
}

// Wire indices of the shifted point to evaluate the interpolant at.
func WiresShiftedEvaluationPoint(subgroupBits int, degree int) [2]int {
	start := StartIntermediates(subgroupBits) + D*2*NumIntermediates(subgroupBits, degree)
	return [2]int{start, start + D}
}
