package goldilocks

import (
	"math"
	"math/big"
	"strconv"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type GoldilocksVariable struct {
	Limb frontend.Variable
}

var MODULUS *big.Int = emulated.Goldilocks{}.Modulus()

func init() {
	solver.RegisterHint(ModulusHint)
}

func lessThan(api frontend.API, rangeChecker frontend.Rangechecker, i1 frontend.Variable, i2 frontend.Variable, n int) {
	if n > 64 {
		panic("LessThan doesnt work for n>64 for now")
	}
	rangeChecker.Check(i1, n)
	rangeChecker.Check(i2, n)
	comp1 := api.Add(i1, strconv.FormatUint(uint64(math.Pow(2, float64(n))), 10))
	comp := api.Sub(comp1, i2)
	comp_binary := api.ToBinary(comp, n+1)
	api.AssertIsEqual(comp_binary[n], 1)
}

func RangeCheck(api frontend.API, rangeChecker frontend.Rangechecker, x frontend.Variable) {
	lessThan(api, rangeChecker, MODULUS, x, 64)
}

func Reduce(api frontend.API, rangeChecker frontend.Rangechecker, x frontend.Variable) GoldilocksVariable {
	result, err := api.Compiler().NewHint(ModulusHint, 2, x)
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
	if len(inputs) != 1 {
		panic("ReduceHint expects 1 input operand")
	}
	input := inputs[0]
	quotient := new(big.Int).Div(input, MODULUS)
	remainder := new(big.Int).Rem(input, MODULUS)
	results[0] = quotient
	results[1] = remainder
	return nil
}
