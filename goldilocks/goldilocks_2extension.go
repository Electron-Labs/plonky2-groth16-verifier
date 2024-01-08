package goldilocks

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

const D = 2
const W = 7
const DTH_ROOT = 18446744069414584320
const TWO_ADICITY_EXT2 = TWO_ADICITY + 1

var EXT_POWER_OF_TWO_GENERATOR = [2]*big.Int{new(big.Int).SetUint64(0), new(big.Int).SetUint64(15659105665374529263)}

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
		A: Reduce(api, rangeChecker, cANoReduce, 131), // TODO: 132?
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

func ExpExt(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	in GoldilocksExtension2Variable,
	degree_in_bits []frontend.Variable,
) GoldilocksExtension2Variable {
	current := in
	product := GetGoldilocksExtensionVariable([]uint64{1, 0})
	for _, bit := range degree_in_bits {
		productXcurrent := MulExt(api, rangeChecker, product, current)
		product.A.Limb = api.Select(bit, productXcurrent.A.Limb, product.A.Limb)
		product.B.Limb = api.Select(bit, productXcurrent.B.Limb, product.B.Limb)
		current = MulExt(api, rangeChecker, current, current)
	}
	return product
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

func SquareExtBigInt(base [2]*big.Int) [2]*big.Int {
	a0 := base[0]
	a1 := base[1]

	a02 := new(big.Int).Mul(a0, a0)
	a12 := new(big.Int).Mul(a1, a1)

	c0 := new(big.Int).Mod(new(big.Int).Add(a02, new(big.Int).Mul(new(big.Int).SetUint64(W), a12)), MODULUS)
	c1 := new(big.Int).Mod(new(big.Int).Mul(a0, new(big.Int).Add(a1, a1)), MODULUS)

	return [2]*big.Int{c0, c1}
}

func ExpPow2ExtBigInt(base [2]*big.Int, power_log int) [2]*big.Int {
	res := base
	for i := 0; i < power_log; i++ {
		res = SquareExtBigInt(res)
	}
	return res
}

func PrimitveRootOfUnityExt(n_log int) GoldilocksExtension2Variable {
	if n_log > TWO_ADICITY_EXT2 {
		panic("n_log more than TWO_ADICITY_EXT2")
	}
	base_pow := ExpPow2ExtBigInt(EXT_POWER_OF_TWO_GENERATOR, TWO_ADICITY_EXT2-n_log)
	var root GoldilocksExtension2Variable
	root.A.Limb = base_pow[0]
	root.B.Limb = base_pow[1]
	return root
}

func SelectGoldilocksExt2(api frontend.API, b frontend.Variable, in1 GoldilocksExtension2Variable, in2 GoldilocksExtension2Variable) GoldilocksExtension2Variable {
	var out GoldilocksExtension2Variable
	out.A.Limb = api.Select(b, in1.A.Limb, in2.A.Limb)
	out.B.Limb = api.Select(b, in1.B.Limb, in2.B.Limb)
	return out
}

func SelectGoldilocksExt2Lookup2(api frontend.API, b0 frontend.Variable, b1 frontend.Variable, in0 GoldilocksExtension2Variable, in1 GoldilocksExtension2Variable, in2 GoldilocksExtension2Variable, in3 GoldilocksExtension2Variable) GoldilocksExtension2Variable {
	var out GoldilocksExtension2Variable
	out.A.Limb = api.Lookup2(b0, b1, in0.A.Limb, in1.A.Limb, in2.A.Limb, in3.A.Limb)
	out.B.Limb = api.Lookup2(b0, b1, in0.B.Limb, in1.B.Limb, in2.B.Limb, in3.B.Limb)
	return out
}

func SelectGoldilocksExt2Recursive(api frontend.API, b []frontend.Variable, in []GoldilocksExtension2Variable) []GoldilocksExtension2Variable {
	if len(in) == 1 {
		return in
	} else if len(in)%4 == 0 {
		two_bits_select := make([]GoldilocksExtension2Variable, len(in)/4)
		for i := 0; i < len(two_bits_select); i++ {
			two_bits_select[i] = SelectGoldilocksExt2Lookup2(api, b[0], b[1], in[4*i], in[4*i+1], in[4*i+2], in[4*i+3])
		}
		return SelectGoldilocksExt2Recursive(api, b[2:], two_bits_select)
	} else {
		// <4 power means len(in) == 2 only
		return []GoldilocksExtension2Variable{SelectGoldilocksExt2(api, b[0], in[1], in[0])}
	}
}

func Flatten(in []GoldilocksExtension2Variable) []GoldilocksVariable {
	out := make([]GoldilocksVariable, len(in)*2)
	for i, v := range in {
		out[2*i] = v.A
		out[2*i+1] = v.B
	}
	return out
}

// TODO: make it FromBase afer moving to a sub-package 'quadratic'
func BaseTo2ExtRaw(x frontend.Variable) [D]frontend.Variable {
	return [D]frontend.Variable{x, 0}
}
func BaseTo2Ext(x GoldilocksVariable) GoldilocksExtension2Variable {
	return GoldilocksExtension2Variable{
		A: x,
		B: GoldilocksVariable{Limb: 0},
	}
}

func ZERO() [D]frontend.Variable {
	return [D]frontend.Variable{0, 0}
}
