package goldilocks

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/consensys/gnark/test"
)

type TestLessThanCircuit struct {
	I1 frontend.Variable
	I2 frontend.Variable
	N  int
}

func (circuit *TestLessThanCircuit) Define(api frontend.API) error {
	rangeChecker := rangecheck.New(api)
	api.AssertIsEqual(LessThan(api, rangeChecker, circuit.I1, circuit.I2, circuit.N), 1)
	return nil
}

func TestLessThan(t *testing.T) {
	assert := test.NewAssert(t)

	type testData struct {
		i1      uint64
		i2      uint64
		n       int
		correct bool
	}

	tests := []testData{
		{i1: 500, i2: 1000, n: 10, correct: true},
		{i1: 5698, i2: 15000, n: 14, correct: true},
		{i1: 1<<64 - 1<<32 - 5000, i2: 1<<64 - 1<<32 + 1, n: 64, correct: true},
		{i1: 15, i2: 10, n: 4, correct: false},
		{i1: 1005, i2: 1005, n: 10, correct: false},
		{i1: 567, i2: 600, n: 5, correct: false},
	}

	for _, t_i := range tests {
		circuit := TestLessThanCircuit{
			N: t_i.n,
		}
		r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			t.Fatal("Error in compiling circuit: ", err)
		}
		var witness TestLessThanCircuit
		witness.I1 = t_i.i1
		witness.I2 = t_i.i2
		w, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal("Error in witness: ", err, "\n test: ", t_i)
		}
		err = r1cs.IsSolved(w)
		if t_i.correct {
			if err != nil {
				t.Fatal("Circuit not solved: ", err, "\n test: ", t_i)
			}
			assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254))
		} else {
			if err == nil {
				t.Log("Circuit solved when it should have failed\n test: ", t_i)
				t.Fail()
			}
		}
	}
}

type TestRangeCheckCircuit struct {
	V frontend.Variable
}

func (circuit *TestRangeCheckCircuit) Define(api frontend.API) error {
	rangeChecker := rangecheck.New(api)
	RangeCheck(api, rangeChecker, circuit.V)
	return nil
}

func TestRangeCheck(t *testing.T) {
	assert := test.NewAssert(t)

	type testData struct {
		v       uint64
		correct bool
	}

	tests := []testData{
		{v: 500, correct: true},
		{v: 1<<64 - 1, correct: false},
		{v: 1<<64 - 1<<32 + 2, correct: false},
		{v: 1<<64 - 1<<32, correct: true},
		{v: 18446744069414581458, correct: true},
	}

	for _, t_i := range tests {
		var circuit TestRangeCheckCircuit
		r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			t.Fatal("Error in compiling circuit: ", err)
		}
		var witness TestRangeCheckCircuit
		witness.V = t_i.v
		w, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal("Error in witness: ", err, "\n test: ", t_i)
		}
		err = r1cs.IsSolved(w)
		if t_i.correct {
			if err != nil {
				t.Fatal("Circuit not solved: ", err, "\n test: ", t_i)
			}
			assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254))
		} else {
			if err == nil {
				t.Log("Circuit solved when it should have failed\n test: ", t_i)
				t.Fail()
			}
		}
	}
}

type TestReduceCircuit struct {
	V        frontend.Variable
	ReducedV frontend.Variable
}

func (circuit *TestReduceCircuit) Define(api frontend.API) error {
	rangeChecker := rangecheck.New(api)
	reducedV := Reduce(api, rangeChecker, circuit.V, 128)
	api.AssertIsEqual(reducedV.Limb, circuit.ReducedV)
	return nil
}

func TestReduce(t *testing.T) {
	assert := test.NewAssert(t)

	type testData struct {
		v        string
		reducedV string
	}

	tests := []testData{
		{v: "500", reducedV: "500"},
		{v: "18446744073709551615", reducedV: "4294967294"},
		{v: "18446744069414584321", reducedV: "0"},
		{v: "18446744069414584320", reducedV: "18446744069414584320"},
		{v: "184467440694145814589", reducedV: "18446744069414555700"},
	}

	for _, t_i := range tests {
		var circuit TestReduceCircuit
		r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			t.Fatal("Error in compiling circuit: ", err)
		}
		var witness TestReduceCircuit
		witness.V = t_i.v
		witness.ReducedV = t_i.reducedV
		w, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal("Error in witness: ", err, "\n test: ", t_i)
		}
		err = r1cs.IsSolved(w)
		if err != nil {
			t.Fatal("Circuit not solved: ", err, "\n test: ", t_i)
		}
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254))
	}
}

type TestArithmeticCircuit struct {
	In1    GoldilocksVariable
	In2    GoldilocksVariable
	AddRes GoldilocksVariable
	MulRes GoldilocksVariable
	SubRes GoldilocksVariable
}

func (circuit *TestArithmeticCircuit) Define(api frontend.API) error {
	rangeChecker := rangecheck.New(api)
	api.AssertIsEqual(Add(api, rangeChecker, circuit.In1, circuit.In2).Limb, circuit.AddRes.Limb)
	api.AssertIsEqual(Mul(api, rangeChecker, circuit.In1, circuit.In2).Limb, circuit.MulRes.Limb)
	api.AssertIsEqual(Sub(api, rangeChecker, circuit.In1, circuit.In2).Limb, circuit.SubRes.Limb)
	return nil
}

func TestArithmetic(t *testing.T) {
	assert := test.NewAssert(t)

	type testData struct {
		in1    big.Int
		in2    big.Int
		addRes big.Int
		mulRes big.Int
		subRes big.Int
	}

	getTest := func(in1 string, in2 string) testData {
		var ret testData
		ret.in1.SetString(in1, 10)
		ret.in2.SetString(in2, 10)
		ret.addRes.Mod(ret.addRes.Add(&ret.in1, &ret.in2), MODULUS)
		ret.mulRes.Mod(ret.mulRes.Mul(&ret.in1, &ret.in2), MODULUS)
		ret.subRes.Mod(ret.subRes.Sub(&ret.in1, &ret.in2), MODULUS)
		return ret
	}

	tests := []testData{
		getTest("5", "36"),
		getTest("18446744069414584271", "9873211"),
		getTest("18446744069414584320", "1"),
		getTest("1984351684", "65498741"),
		getTest("0", "18446744069414584320"),
	}

	var circuit TestArithmeticCircuit
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal("Error in compiling circuit: ", err)
	}

	for _, t_i := range tests {
		var witness TestArithmeticCircuit
		witness.In1 = GetGoldilocksVariable(t_i.in1.Uint64())
		witness.In2 = GetGoldilocksVariable(t_i.in2.Uint64())
		witness.AddRes = GetGoldilocksVariable(t_i.addRes.Uint64())
		witness.MulRes = GetGoldilocksVariable(t_i.mulRes.Uint64())
		witness.SubRes = GetGoldilocksVariable(t_i.subRes.Uint64())
		w, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal("Error in witness: ", err, "\n test: ", t_i)
		}
		err = r1cs.IsSolved(w)
		if err != nil {
			t.Fatal("Circuit not solved: ", err, "\n test: ", t_i)
		}
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254))
	}
}

type TestInverseCircuit struct {
	In     GoldilocksVariable
	InvRes GoldilocksVariable
}

func (circuit *TestInverseCircuit) Define(api frontend.API) error {
	rangeChecker := rangecheck.New(api)
	api.AssertIsEqual(Inv(api, rangeChecker, circuit.In).Limb, circuit.InvRes.Limb)
	return nil
}

func TestInverse(t *testing.T) {
	assert := test.NewAssert(t)

	type testData struct {
		in     big.Int
		invRes big.Int
	}

	getTest := func(in string) testData {
		var ret testData
		ret.in.SetString(in, 10)
		ret.invRes.ModInverse(&ret.in, MODULUS)
		return ret
	}

	tests := []testData{
		getTest("5"),
		getTest("1984351684"),
		getTest("65498741"),
		getTest("18446744069414584271"),
		getTest("18446744069414584320"),
		getTest("1"),
	}

	var circuit TestInverseCircuit
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal("Error in compiling circuit: ", err)
	}

	for _, t_i := range tests {
		var witness TestInverseCircuit
		witness.In = GetGoldilocksVariable(t_i.in.Uint64())
		witness.InvRes = GetGoldilocksVariable(t_i.invRes.Uint64())
		w, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal("Error in witness: ", err, "\n test: ", t_i)
		}
		err = r1cs.IsSolved(w)
		if err != nil {
			t.Fatal("Circuit not solved: ", err, "\n test: ", t_i)
		}
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254))
	}
}
