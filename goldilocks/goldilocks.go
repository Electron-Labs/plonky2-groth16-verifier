package goldilocks

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type GoldilocksVariable struct {
	Limb frontend.Variable
}

type ProofVariable2 struct {
	X frontend.Variable
}

func GetGoldilocksVariable(vals uint64) GoldilocksVariable {
	e := GoldilocksVariable{
		Limb: vals,
	}

	return e
}

func GetGoldilocksVariableArr(vals []uint64) []GoldilocksVariable {
	var variable []GoldilocksVariable
	for _, elm := range vals {
		variable = append(variable, GetGoldilocksVariable(elm))
	}

	return variable
}

var MODULUS *big.Int = emulated.Goldilocks{}.Modulus()

func init() {
	solver.RegisterHint(ModulusHint)
	solver.RegisterHint(InverseHint)
}

func getGoldilocks(i frontend.Variable) GoldilocksVariable {
	return GoldilocksVariable{Limb: i}
}

func LessThan(api frontend.API, rangeChecker frontend.Rangechecker, i1 frontend.Variable, i2 frontend.Variable, n int) {
	if n > 64 {
		panic("LessThan doesnt work for n>64 for now")
	}
	rangeChecker.Check(i1, n)
	rangeChecker.Check(i2, n)
	var comp1 frontend.Variable
	if n < 64 {
		comp1 = api.Add(i1, 1<<n)
	} else {
		comp1 = api.Add(i1, "18446744073709551616")
	}
	comp := api.Sub(comp1, i2)
	comp_binary := api.ToBinary(comp, n+1)
	api.AssertIsEqual(comp_binary[n], 0)
}

func RangeCheck(api frontend.API, rangeChecker frontend.Rangechecker, x frontend.Variable) {
	LessThan(api, rangeChecker, x, (&big.Int{}).Add(big.NewInt(1), MODULUS), 64)
}

func Reduce(api frontend.API, rangeChecker frontend.Rangechecker, x frontend.Variable) GoldilocksVariable {
	result, err := api.Compiler().NewHint(ModulusHint, int(2), x, MODULUS)
	if err != nil {
		panic(err)
	}
	// 190 Explanation? (So that (quotient * MODULUS) doesnt overflow)
	rangeChecker.Check(result[0], 190)
	api.AssertIsEqual(api.Add(api.Mul(result[0], MODULUS), result[1]), x)

	RangeCheck(api, rangeChecker, result[1])

	return GoldilocksVariable{Limb: result[1]}
}

func ModulusHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 2 {
		panic("ReduceHint expects 2 input operand")
	}
	quotient := new(big.Int).Div(inputs[0], inputs[1])
	remainder := new(big.Int).Rem(inputs[0], inputs[1])
	results[0] = quotient
	results[1] = remainder
	return nil
}

func Add(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	in1 GoldilocksVariable,
	in2 GoldilocksVariable,
) GoldilocksVariable {
	res := api.Add(in1.Limb, in2.Limb)
	return Reduce(api, rangeChecker, res)
}

func Mul(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	in1 GoldilocksVariable,
	in2 GoldilocksVariable,
) GoldilocksVariable {
	res := api.Mul(in1.Limb, in2.Limb)
	return Reduce(api, rangeChecker, res)
}

func Sub(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	in1 GoldilocksVariable,
	in2 GoldilocksVariable,
) GoldilocksVariable {
	res := api.Add(api.Sub(in1.Limb, in2.Limb), MODULUS)
	return Reduce(api, rangeChecker, res)
}

func Inv(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	in GoldilocksVariable,
) GoldilocksVariable {
	res, err := api.Compiler().NewHint(InverseHint, 1, in.Limb)
	if err != nil {
		panic(err)
	}
	inv := GoldilocksVariable{Limb: res[0]}
	api.AssertIsEqual(Mul(api, rangeChecker, in, inv).Limb, 1)
	return inv
}

func InverseHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	output := outputs[0]

	output.Set(inputs[0])

	output.ModInverse(output, MODULUS)
	return nil
}
