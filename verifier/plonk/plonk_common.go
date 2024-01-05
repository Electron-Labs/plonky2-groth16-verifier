package plonk

import (
	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark/frontend"
)

func eval_zero_poly(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	x_pow_deg goldilocks.GoldilocksExtension2Variable,
) goldilocks.GoldilocksExtension2Variable {
	x_pow_deg.A.Limb = api.Sub(x_pow_deg.A.Limb, 1)
	return x_pow_deg
}

func EvalL0(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	degree_bits int,
	x goldilocks.GoldilocksExtension2Variable,
	x_pow_deg goldilocks.GoldilocksExtension2Variable,
) goldilocks.GoldilocksExtension2Variable {
	numerator := eval_zero_poly(api, rangeChecker, x_pow_deg)
	x_minus_one := x
	x_minus_one.A.Limb = api.Sub(x_minus_one.A.Limb, 1)
	denominator := goldilocks.ScalarMul(api, rangeChecker, goldilocks.GetGoldilocksVariable(uint64(1<<degree_bits)), x_minus_one)

	return goldilocks.DivExt(api, rangeChecker, numerator, denominator)
}
