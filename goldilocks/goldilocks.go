package goldilocks

import (
	"math"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

const TWO_ADICITY = 32
const MULTIPLICATIVE_GROUP_GENERATOR = 7

var POWER_OF_TWO_GENERATOR = new(big.Int).SetUint64(1753635133440165772)

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
	solver.RegisterHint(GoldilocksRangeCheckHint)
}

func GetGoldilocks(i frontend.Variable) GoldilocksVariable {
	return GoldilocksVariable{Limb: i}
}

func LessThan(api frontend.API, rangeChecker frontend.Rangechecker, i1 frontend.Variable, i2 frontend.Variable, n int) frontend.Variable {
	comp1 := api.Add(i1, new(big.Int).Lsh(big.NewInt(1), uint(n)))
	comp := api.Sub(comp1, i2)
	comp_binary := api.ToBinary(comp, n+1)
	return api.Sub(1, comp_binary[n])
}

func GoldilocksRangeCheckHint(p *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 1 {
		panic("Incorrect number of inputs to hint")
	}
	outputs[0] = new(big.Int).And(inputs[0], big.NewInt(math.MaxUint32))
	outputs[1] = new(big.Int).Rsh(inputs[0], 32)
	return nil
}

func RangeCheck(api frontend.API, rangeChecker frontend.Rangechecker, x frontend.Variable) {
	outputs, err := api.Compiler().NewHint(GoldilocksRangeCheckHint, 2, x)
	if err != nil {
		panic("Error in Goldilocks range check hint")
	}
	low_bits := outputs[0]
	high_bits := outputs[1]
	rangeChecker.Check(low_bits, 32)
	rangeChecker.Check(high_bits, 32)
	api.AssertIsEqual(
		x,
		api.Add(api.Mul(high_bits, 1<<32), low_bits),
	)
	//[NOTE] Since some values in proof_with_pis returned from plonky2 are equal to 2**64 - 2**32 + 1
	// we need to include a check for it too. we an reduce but it would blow up the constraints
	api.AssertIsEqual(
		api.Select(
			api.IsZero(api.Sub(math.MaxUint32, high_bits)),
			api.Select(api.IsZero(low_bits), 1, api.IsZero(api.Sub(low_bits, 1))),
			1,
		),
		1,
	)
}

func Reduce(api frontend.API, rangeChecker frontend.Rangechecker, x frontend.Variable, n int) GoldilocksVariable {
	result, err := api.Compiler().NewHint(ModulusHint, int(2), x, MODULUS)
	if err != nil {
		panic(err)
	}
	rangeChecker.Check(result[0], max(1, n-64))
	rangeChecker.Check(result[1], 64)
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

func Neg(
	api frontend.API,
	in GoldilocksVariable,
) GoldilocksVariable {
	return GoldilocksVariable{
		Limb: api.Sub(MODULUS, in.Limb),
	}
}

func Add(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	in1 GoldilocksVariable,
	in2 GoldilocksVariable,
) GoldilocksVariable {
	res := api.Add(in1.Limb, in2.Limb)
	return Reduce(api, rangeChecker, res, 65)
}

func Mul(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	in1 GoldilocksVariable,
	in2 GoldilocksVariable,
) GoldilocksVariable {
	res := api.Mul(in1.Limb, in2.Limb)
	return Reduce(api, rangeChecker, res, 128)
}

func Sub(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	in1 GoldilocksVariable,
	in2 GoldilocksVariable,
) GoldilocksVariable {
	res := api.Add(api.Sub(in1.Limb, in2.Limb), MODULUS)
	return Reduce(api, rangeChecker, res, 65)
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

func ExpPow2(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	in GoldilocksVariable,
	degree_bits int,
) GoldilocksVariable {
	out := in
	for i := 0; i < degree_bits; i++ {
		out = Mul(api, rangeChecker, out, out)
	}
	return out
}

func Exp(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	in GoldilocksVariable,
	degree_in_bits []frontend.Variable,
) GoldilocksVariable {
	current := in
	product := GetGoldilocksVariable(1)
	for _, bit := range degree_in_bits {
		productXcurrent := Mul(api, rangeChecker, product, current)
		product.Limb = api.Select(bit, productXcurrent.Limb, product.Limb)
		current = Mul(api, rangeChecker, current, current)
	}
	return product
}

func ExpPow2BigInt(base *big.Int, power_log int) *big.Int {
	res := base
	for i := 0; i < power_log; i++ {
		res = new(big.Int).Mod(new(big.Int).Mul(res, res), MODULUS)
	}
	return res
}

func PrimitveRootOfUnity(n_log int) GoldilocksVariable {
	if n_log > TWO_ADICITY {
		panic("n_log more than TWO_ADICITY_EXT2")
	}
	base_pow := ExpPow2BigInt(POWER_OF_TWO_GENERATOR, TWO_ADICITY-n_log)
	var root GoldilocksVariable
	root.Limb = base_pow
	return root
}

func TwoAdicSubgroup(api frontend.API, rangeChecker frontend.Rangechecker, nLog int) []GoldilocksVariable {
	generator := PrimitveRootOfUnity(nLog)
	powers := make([]GoldilocksVariable, 1<<nLog)

	powers[0] = GoldilocksVariable{Limb: 1}
	for i := 1; i < 1<<nLog; i++ {
		powers[i] = Mul(api, rangeChecker, powers[i-1], generator)
	}
	return powers
}
