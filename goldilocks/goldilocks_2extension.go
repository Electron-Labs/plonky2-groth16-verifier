package goldilocks

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

const W = 7
const DTH_ROOT = 18446744069414584320

type GoldilocksExtension2Variable struct {
	A GoldilocksVariable
	B GoldilocksVariable
}

func (goldilocks_extension2 *GoldilocksExtension2Variable) RangeCheck(api frontend.API, rangeChecker frontend.Rangechecker) {
	RangeCheck(api, rangeChecker, goldilocks_extension2.A.Limb)
	RangeCheck(api, rangeChecker, goldilocks_extension2.B.Limb)
}

func GetGoldilocksExtensionVariable(vals []uint64) GoldilocksExtension2Variable {
	e0 := GetGoldilocksVariable(vals[0])
	e1 := GetGoldilocksVariable(vals[1])
	e := GoldilocksExtension2Variable{
		A: e0,
		B: e1,
	}

	return e
}

func GetGoldilocksExtensionVariableArr(vals [][]uint64) []GoldilocksExtension2Variable {
	var extensionVariable []GoldilocksExtension2Variable
	for _, elm := range vals {
		extensionVariable = append(extensionVariable, GetGoldilocksExtensionVariable(elm))
	}

	return extensionVariable
}

func GetVariableArray(in GoldilocksExtension2Variable) [2]frontend.Variable {
	return [2]frontend.Variable{in.A.Limb, in.B.Limb}
}

func init() {
	solver.RegisterHint(InvExtHint)
}

func NegExt(
	api frontend.API,
	in GoldilocksExtension2Variable,
) GoldilocksExtension2Variable {
	return GoldilocksExtension2Variable{
		A: Neg(api, in.A),
		B: Neg(api, in.B),
	}
}

func AddExt(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	in1 GoldilocksExtension2Variable,
	in2 GoldilocksExtension2Variable,
) GoldilocksExtension2Variable {
	return GoldilocksExtension2Variable{
		A: Add(api, rangeChecker, in1.A, in2.A),
		B: Add(api, rangeChecker, in1.B, in2.B),
	}
}

func AddExtNoReduce(
	api frontend.API,
	in1 [2]frontend.Variable,
	in2 [2]frontend.Variable,
) [2]frontend.Variable {
	return [2]frontend.Variable{
		api.Add(in1[0], in2[0]),
		api.Add(in1[1], in2[1]),
	}
}

func SubExt(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	in1 GoldilocksExtension2Variable,
	in2 GoldilocksExtension2Variable,
) GoldilocksExtension2Variable {
	return GoldilocksExtension2Variable{
		A: Sub(api, rangeChecker, in1.A, in2.A),
		B: Sub(api, rangeChecker, in1.B, in2.B),
	}
}

func SubExtNoReduce(
	api frontend.API,
	in1 [2]frontend.Variable,
	in2 [2]frontend.Variable,
) [2]frontend.Variable {
	cANoReduce := api.Add(api.Sub(in1[0], in2[0]), MODULUS)
	cBNoReduce := api.Add(api.Sub(in1[1], in2[1]), MODULUS)

	return [2]frontend.Variable{cANoReduce, cBNoReduce}
}

func ScalarMul(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	s GoldilocksVariable,
	x GoldilocksExtension2Variable,
) GoldilocksExtension2Variable {
	return GoldilocksExtension2Variable{
		A: Mul(api, rangeChecker, s, x.A),
		B: Mul(api, rangeChecker, s, x.B),
	}
}

func ScalarMulNoReduce(
	api frontend.API,
	s frontend.Variable,
	x [2]frontend.Variable,
) [2]frontend.Variable {
	return [2]frontend.Variable{
		api.Mul(s, x[0]),
		api.Mul(s, x[1]),
	}
}

func MulExt(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	in1 GoldilocksExtension2Variable,
	in2 GoldilocksExtension2Variable,
) GoldilocksExtension2Variable {
	cANoReduce := api.Add(api.Mul(in1.A.Limb, in2.A.Limb), api.Mul(in1.B.Limb, in2.B.Limb, W))
	cBNoReduce := api.Add(api.Mul(in1.A.Limb, in2.B.Limb), api.Mul(in1.B.Limb, in2.A.Limb))

	return GoldilocksExtension2Variable{
		A: Reduce(api, rangeChecker, cANoReduce, 131),
		B: Reduce(api, rangeChecker, cBNoReduce, 129),
	}
}

func MulExtNoReduce(
	api frontend.API,
	in1 [2]frontend.Variable,
	in2 [2]frontend.Variable,
) [2]frontend.Variable {
	cANoReduce := api.Add(api.Mul(in1[0], in2[0]), api.Mul(in1[1], in2[1], W))
	cBNoReduce := api.Add(api.Mul(in1[0], in2[1]), api.Mul(in1[1], in2[0]))

	return [2]frontend.Variable{cANoReduce, cBNoReduce}
}

func ExpPow2Ext(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	in GoldilocksExtension2Variable,
	degree_bits int,
) GoldilocksExtension2Variable {
	out := in
	for i := 0; i < degree_bits; i++ {
		out = MulExt(api, rangeChecker, out, out)
	}
	return out
}

func DivExt(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	numerator GoldilocksExtension2Variable,
	denominator GoldilocksExtension2Variable,
) GoldilocksExtension2Variable {
	denominator_inv := InvExt(api, rangeChecker, denominator)

	return MulExt(api, rangeChecker, numerator, denominator_inv)
}

func InvExt(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	in GoldilocksExtension2Variable,
) GoldilocksExtension2Variable {
	res, err := api.Compiler().NewHint(InvExtHint, 2, in.A.Limb, in.B.Limb)
	if err != nil {
		panic("Failed to compute extension inverse")
	}
	var inv GoldilocksExtension2Variable
	inv.A.Limb = res[0]
	inv.B.Limb = res[1]
	m := MulExt(api, rangeChecker, in, inv)
	api.AssertIsEqual(m.A.Limb, 1)
	api.AssertIsEqual(m.B.Limb, 0)
	return inv
}

func InvExtHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 2 {
		panic("wrong number of inputs")
	}
	forbenius_A := inputs[0]
	forbenius_B := new(big.Int).Mod(new(big.Int).Mul(inputs[1], new(big.Int).SetUint64(DTH_ROOT)), MODULUS)

	a_pow_r := new(big.Int).Add(
		new(big.Int).Mul(inputs[0], forbenius_A),
		new(big.Int).Mul(new(big.Int).Mul(inputs[1], forbenius_B), big.NewInt(W)),
	)
	a_pow_r.Mod(a_pow_r, MODULUS)

	a_pow_r_inv := new(big.Int).ModInverse(a_pow_r, MODULUS)
	outputs[0] = new(big.Int).Mod(new(big.Int).Mul(forbenius_A, a_pow_r_inv), MODULUS)
	outputs[1] = new(big.Int).Mod(new(big.Int).Mul(forbenius_B, a_pow_r_inv), MODULUS)
	return nil
}
