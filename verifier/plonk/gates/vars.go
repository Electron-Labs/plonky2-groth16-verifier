package gates

import (
	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/types"
	"github.com/consensys/gnark/frontend"
)

type EvaluationVars struct {
	LocalConstants   []goldilocks.GoldilocksExtension2Variable
	LocalWires       []goldilocks.GoldilocksExtension2Variable
	PublicInputsHash types.HashOutVariable
}

func (vars *EvaluationVars) RemovePrefix(num_selectors int) {
	vars.LocalConstants = vars.LocalConstants[num_selectors:]
}

func ReduceWithPowersMulti(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	terms []goldilocks.GoldilocksExtension2Variable,
	alphas []goldilocks.GoldilocksExtension2Variable,
) []goldilocks.GoldilocksExtension2Variable {
	cumul := make([]goldilocks.GoldilocksExtension2Variable, len(alphas))
	for i := range cumul {
		cumul[i] = goldilocks.GetGoldilocksExtensionVariable([]uint64{0, 0})
	}
	for t_i := len(terms) - 1; t_i >= 0; t_i-- {
		term := terms[t_i]
		for i := range cumul {
			mul := goldilocks.MulExtNoReduce(api, goldilocks.GetVariableArray(cumul[i]), goldilocks.GetVariableArray(alphas[i]))
			acc := goldilocks.AddExtNoReduce(api, goldilocks.GetVariableArray(term), mul)
			cumul[i] = goldilocks.GoldilocksExtension2Variable{
				A: goldilocks.Reduce(api, rangeChecker, acc[0], 128),
				B: goldilocks.Reduce(api, rangeChecker, acc[1], 128),
			}
		}
	}
	return cumul
}

func ReduceWithPowers(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	terms []goldilocks.GoldilocksExtension2Variable,
	alpha goldilocks.GoldilocksExtension2Variable,
) goldilocks.GoldilocksExtension2Variable {
	sum := goldilocks.GetGoldilocksExtensionVariable([]uint64{0, 0})
	for i := len(terms) - 1; i >= 0; i-- {
		mul := goldilocks.MulExtNoReduce(api, goldilocks.GetVariableArray(sum), goldilocks.GetVariableArray(alpha))
		acc := goldilocks.AddExtNoReduce(api, goldilocks.GetVariableArray(terms[i]), mul)
		sum = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, acc[0], 131),
			B: goldilocks.Reduce(api, rangeChecker, acc[1], 129),
		}
	}
	return sum
}
