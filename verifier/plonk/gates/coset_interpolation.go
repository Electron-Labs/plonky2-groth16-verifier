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
	splits := strings.Split(id, ", _phantom")
	if splits[1] != ": PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>" {
		panic(fmt.Sprintln("Invalid gate id: ", id))
	}
	id = splits[0]
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
	numConstraints := gate.numConstraints()
	numPoints := gate.numPoints()

	constraints := make([]goldilocks.GoldilocksExtension2Variable, numConstraints)

	shift := goldilocks.GetVariableArray(vars.LocalWires[gate.wireShift()])
	evaluationPoint := GetLocalExtAlgebra(vars.LocalWires, gate.wiresEvaluationPoint())
	shiftedEvaluationPoint := GetLocalExtAlgebra(vars.LocalWires, gate.wiresShiftedEvaluationPoint())

	a := algebra.ScalarMulNoReduce(api, shiftedEvaluationPoint, shift)

	constraintNoReduce := algebra.SubNoReduce(api, a, evaluationPoint)
	constraints[0] = goldilocks.NegExt(api,
		goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0][0], 132),
			B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0][1], 130)},
	)
	constraints[1] = goldilocks.NegExt(api,
		goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1][0], 132),
			B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1][1], 130)},
	)

	domain := goldilocks.TwoAdicSubgroup(api, rangeChecker, gate.SubgroupBits)
	values := make([][2][2]frontend.Variable, numPoints)
	for i := 0; i < numPoints; i++ {
		values[i] = GetLocalExtAlgebra(vars.LocalWires, gate.wiresValue(i))
	}

	weights := make([]frontend.Variable, len(gate.BarycentricWeights))
	for i := 0; i < len(weights); i++ {
		weights[i] = frontend.Variable(gate.BarycentricWeights[i])
	}

	computedEval, computedProd := gate.PartialInterpolateExtAlgebra(
		api,
		rangeChecker,
		domain[:gate.Degree],
		values[:gate.Degree],
		weights[:gate.Degree],
		shiftedEvaluationPoint,
		algebra.ZERO(),
		algebra.FromBase(goldilocks.BaseTo2ExtRaw(1)),
	)

	numIntermediates := gate.numIntermediates()
	for i := 0; i < numIntermediates; i++ {
		intermediateEval := GetLocalExtAlgebra(vars.LocalWires, gate.wiresIntermediateEval(i))
		intermediateProd := GetLocalExtAlgebra(vars.LocalWires, gate.wiresIntermediateProd(i))

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

		startIndex := 1 + (gate.Degree-1)*(i+1)
		endIndex := min(startIndex+gate.Degree-1, numPoints)

		computedEval, computedProd = gate.PartialInterpolateExtAlgebra(
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

	evaluationValue := GetLocalExtAlgebra(vars.LocalWires, gate.wiresEvaluationValue())

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

func (gate *CosetInterpolationGate) PartialInterpolateExtAlgebra(
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
		termNoReduce := algebra.SubNoReduce(api, x, algebra.FromBase(goldilocks.BaseTo2ExtRaw(xi)))
		evalNoReduce := algebra.AddNoReduce(api, algebra.MulNoReduce(api, eval, termNoReduce), algebra.MulNoReduce(api, val, termsPartialProd))
		termsPartialProdNoReduce := algebra.MulNoReduce(api, termsPartialProd, termNoReduce)

		eval = [D][D]frontend.Variable{
			{goldilocks.Reduce(api, rangeChecker, evalNoReduce[0][0], 203).Limb, goldilocks.Reduce(api, rangeChecker, evalNoReduce[0][1], 202).Limb},
			{goldilocks.Reduce(api, rangeChecker, evalNoReduce[1][0], 200).Limb, goldilocks.Reduce(api, rangeChecker, evalNoReduce[1][1], 199).Limb},
		}
		termsPartialProd = [D][D]frontend.Variable{
			{goldilocks.Reduce(api, rangeChecker, termsPartialProdNoReduce[0][0], 137).Limb, goldilocks.Reduce(api, rangeChecker, termsPartialProdNoReduce[0][1], 134).Limb},
			{goldilocks.Reduce(api, rangeChecker, termsPartialProdNoReduce[1][0], 133).Limb, goldilocks.Reduce(api, rangeChecker, termsPartialProdNoReduce[1][1], 130).Limb},
		}
	}

	return eval, termsPartialProd
}

func (gate *CosetInterpolationGate) numConstraints() int {
	// D constraints to check for consistency of the shifted evaluation point, plus D
	// constraints for the evaluation value.
	return D + D + 2*D*gate.numIntermediates()
}

func (gate *CosetInterpolationGate) numPoints() int {
	return 1 << gate.SubgroupBits
}

// Wire index of the coset shift.
func (gate *CosetInterpolationGate) wireShift() int {
	return 0
}

func (gate *CosetInterpolationGate) startValues() int {
	return 1
}

// Wire indices of the `i`th interpolant value.
func (gate *CosetInterpolationGate) wiresValue(i int) [2]int {
	start := gate.startValues() + i*D
	return [2]int{start, start + D}
}

func (gate *CosetInterpolationGate) startEvaluationPoint() int {
	return gate.startValues() + gate.numPoints()*D
}

// Wire indices of the point to evaluate the interpolant at.
func (gate *CosetInterpolationGate) wiresEvaluationPoint() [2]int {
	start := gate.startEvaluationPoint()
	return [2]int{start, start + D}
}

func (gate *CosetInterpolationGate) numIntermediates() int {
	return (gate.numPoints() - 2) / (gate.Degree - 1)
}

// The wires corresponding to the i'th intermediate evaluation.
func (gate *CosetInterpolationGate) wiresIntermediateEval(i int) [2]int {
	start := gate.startIntermediates() + D*i
	return [2]int{start, start + D}
}

// The wires corresponding to the i'th intermediate product.
func (gate *CosetInterpolationGate) wiresIntermediateProd(i int) [2]int {
	start := gate.startIntermediates() + D*(gate.numIntermediates()+i)
	return [2]int{start, start + D}
}

func (gate *CosetInterpolationGate) startEvaluationValue() int {
	return gate.startEvaluationPoint() + D
}

// Wire indices of the interpolated value.
func (gate *CosetInterpolationGate) wiresEvaluationValue() [2]int {
	start := gate.startEvaluationValue()
	return [2]int{start, start + D}
}

func (gate *CosetInterpolationGate) startIntermediates() int {
	return gate.startEvaluationValue() + D
}

// Wire indices of the shifted point to evaluate the interpolant at.
func (gate *CosetInterpolationGate) wiresShiftedEvaluationPoint() [2]int {
	start := gate.startIntermediates() + D*2*gate.numIntermediates()
	return [2]int{start, start + D}
}
