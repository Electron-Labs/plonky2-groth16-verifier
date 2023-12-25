package gates

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/types"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/consensys/gnark/test"
)

type Vars struct {
	LocalConstants   [][]uint64    `json:"local_constants"`
	LocalWires       [][]uint64    `json:"local_wires"`
	PublicInputsHash types.HashOut `json:"public_inputs_hash"`
}

type TestData struct {
	Vars        Vars       `json:"vars"`
	Constraints [][]uint64 `json:"constraints"`
}

type TestGateCircuit struct {
	Vars        EvaluationVars
	Constraints []goldilocks.GoldilocksExtension2Variable
	GateId      string
}

func (circuit *TestGateCircuit) Define(api frontend.API) error {
	rangeChecker := rangecheck.New(api)
	gate := ParseGate(circuit.GateId)
	// TODO:
	// gate.EvalUnfiltered(api, rangeChecker, circuit.Vars)
	contraints := gate.EvalUnfiltered(api, rangeChecker, circuit.Vars)
	for i, v := range contraints {
		api.AssertIsEqual(v.A.Limb, circuit.Constraints[i].A.Limb)
		api.AssertIsEqual(v.B.Limb, circuit.Constraints[i].B.Limb)
	}
	return nil
}

func TestArithmeticGate(t *testing.T) {
	assert := test.NewAssert(t)

	fileName := "../../../testdata/airthmetic_constraints.json"
	fileData, err := os.ReadFile(fileName)
	if err != nil {
		panic(fmt.Sprintln("fail to read file: ", fileName, err))
	}

	var tData TestData

	err = json.Unmarshal(fileData, &tData)
	if err != nil {
		panic(fmt.Sprintln("fail to deserialize: ", err))
	}

	var circuit TestGateCircuit
	circuit.Vars.PublicInputsHash = tData.Vars.PublicInputsHash.GetVariable()
	circuit.Vars.LocalConstants = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalConstants)
	circuit.Vars.LocalWires = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalWires)
	circuit.Constraints = goldilocks.GetGoldilocksExtensionVariableArr(tData.Constraints)
	circuit.GateId = "ArithmeticGate { num_ops: 20 }"

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal("failed to compile: ", err)
	}

	t.Log(r1cs.GetNbConstraints())

	var assignment TestGateCircuit
	assignment.Vars.PublicInputsHash = tData.Vars.PublicInputsHash.GetVariable()
	assignment.Vars.LocalConstants = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalConstants)
	assignment.Vars.LocalWires = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalWires)
	assignment.Constraints = goldilocks.GetGoldilocksExtensionVariableArr(tData.Constraints)
	assignment.GateId = "ArithmeticGate { num_ops: 20 }"

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal("Error in witness: ", err)
	}

	err = r1cs.IsSolved(witness)
	if err != nil {
		t.Fatal("failed to solve: ", err)
	}

	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BN254))
}

func TestArithmeticExtensionGate(t *testing.T) {
	assert := test.NewAssert(t)

	fileName := "../../../testdata/arithmetic_extension_constraints.json"
	fileData, err := os.ReadFile(fileName)
	if err != nil {
		panic(fmt.Sprintln("fail to read file: ", fileName, err))
	}

	var tData TestData

	err = json.Unmarshal(fileData, &tData)
	if err != nil {
		panic(fmt.Sprintln("fail to deserialize: ", err))
	}

	var circuit TestGateCircuit
	circuit.Vars.PublicInputsHash = tData.Vars.PublicInputsHash.GetVariable()
	circuit.Vars.LocalConstants = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalConstants)
	circuit.Vars.LocalWires = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalWires)
	circuit.Constraints = goldilocks.GetGoldilocksExtensionVariableArr(tData.Constraints)
	circuit.GateId = "ArithmeticExtensionGate { num_ops: 10 }"

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal("failed to compile: ", err)
	}

	t.Log(r1cs.GetNbConstraints())

	var assignment TestGateCircuit
	assignment.Vars.PublicInputsHash = tData.Vars.PublicInputsHash.GetVariable()
	assignment.Vars.LocalConstants = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalConstants)
	assignment.Vars.LocalWires = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalWires)
	assignment.Constraints = goldilocks.GetGoldilocksExtensionVariableArr(tData.Constraints)
	assignment.GateId = "ArithmeticExtensionGate { num_ops: 10 }"

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal("Error in witness: ", err)
	}

	err = r1cs.IsSolved(witness)
	if err != nil {
		t.Fatal("failed to solve: ", err)
	}

	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BN254))
}

func TestCosetInterpolationGate(t *testing.T) {
	assert := test.NewAssert(t)

	fileName := "../../../testdata/coset_interpolation_constraints.json"
	fileData, err := os.ReadFile(fileName)
	if err != nil {
		panic(fmt.Sprintln("fail to read file: ", fileName, err))
	}

	var tData TestData

	err = json.Unmarshal(fileData, &tData)
	if err != nil {
		panic(fmt.Sprintln("fail to deserialize: ", err))
	}

	var circuit TestGateCircuit
	circuit.Vars.PublicInputsHash = tData.Vars.PublicInputsHash.GetVariable()
	circuit.Vars.LocalConstants = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalConstants)
	circuit.Vars.LocalWires = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalWires)
	circuit.Constraints = goldilocks.GetGoldilocksExtensionVariableArr(tData.Constraints)
	circuit.GateId = "CosetInterpolationGate { subgroup_bits: 4, degree: 6, barycentric_weights: [17293822565076172801, 18374686475376656385, 18446744069413535745, 281474976645120, 17592186044416, 256, 18446744000695107601, 18446744065119617025, 1152921504338411520, 72057594037927936, 1048576, 18446462594437939201, 18446726477228539905, 18446744069414584065, 68719476720, 4294967296], _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>"

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal("failed to compile: ", err)
	}

	t.Log(r1cs.GetNbConstraints())

	var assignment TestGateCircuit
	assignment.Vars.PublicInputsHash = tData.Vars.PublicInputsHash.GetVariable()
	assignment.Vars.LocalConstants = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalConstants)
	assignment.Vars.LocalWires = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalWires)
	assignment.Constraints = goldilocks.GetGoldilocksExtensionVariableArr(tData.Constraints)
	assignment.GateId = "CosetInterpolationGate { subgroup_bits: 4, degree: 6, barycentric_weights: [17293822565076172801, 18374686475376656385, 18446744069413535745, 281474976645120, 17592186044416, 256, 18446744000695107601, 18446744065119617025, 1152921504338411520, 72057594037927936, 1048576, 18446462594437939201, 18446726477228539905, 18446744069414584065, 68719476720, 4294967296], _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>"

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal("Error in witness: ", err)
	}

	err = r1cs.IsSolved(witness)
	if err != nil {
		t.Fatal("failed to solve: ", err)
	}

	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BN254))
}

func TestConstantGate(t *testing.T) {
	assert := test.NewAssert(t)

	fileName := "../../../testdata/constant_constraints.json"
	fileData, err := os.ReadFile(fileName)
	if err != nil {
		panic(fmt.Sprintln("fail to read file: ", fileName, err))
	}

	var tData TestData

	err = json.Unmarshal(fileData, &tData)
	if err != nil {
		panic(fmt.Sprintln("fail to deserialize: ", err))
	}

	var circuit TestGateCircuit
	circuit.Vars.PublicInputsHash = tData.Vars.PublicInputsHash.GetVariable()
	circuit.Vars.LocalConstants = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalConstants)
	circuit.Vars.LocalWires = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalWires)
	circuit.Constraints = goldilocks.GetGoldilocksExtensionVariableArr(tData.Constraints)
	circuit.GateId = "ConstantGate { num_consts: 2 }"

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal("failed to compile: ", err)
	}

	t.Log(r1cs.GetNbConstraints())

	var assignment TestGateCircuit
	assignment.Vars.PublicInputsHash = tData.Vars.PublicInputsHash.GetVariable()
	assignment.Vars.LocalConstants = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalConstants)
	assignment.Vars.LocalWires = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalWires)
	assignment.Constraints = goldilocks.GetGoldilocksExtensionVariableArr(tData.Constraints)
	assignment.GateId = "ConstantGate { num_consts: 2 }"

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal("Error in witness: ", err)
	}

	err = r1cs.IsSolved(witness)
	if err != nil {
		t.Fatal("failed to solve: ", err)
	}

	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BN254))
}

func TestPublicInputGate(t *testing.T) {
	assert := test.NewAssert(t)

	fileName := "../../../testdata/public_input_constraints.json"
	fileData, err := os.ReadFile(fileName)
	if err != nil {
		panic(fmt.Sprintln("fail to read file: ", fileName, err))
	}

	var tData TestData

	err = json.Unmarshal(fileData, &tData)
	if err != nil {
		panic(fmt.Sprintln("fail to deserialize: ", err))
	}

	var circuit TestGateCircuit
	circuit.Vars.PublicInputsHash = tData.Vars.PublicInputsHash.GetVariable()
	circuit.Vars.LocalConstants = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalConstants)
	circuit.Vars.LocalWires = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalWires)
	circuit.Constraints = goldilocks.GetGoldilocksExtensionVariableArr(tData.Constraints)
	circuit.GateId = "PublicInputGate"

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal("failed to compile: ", err)
	}

	t.Log(r1cs.GetNbConstraints())

	var assignment TestGateCircuit
	assignment.Vars.PublicInputsHash = tData.Vars.PublicInputsHash.GetVariable()
	assignment.Vars.LocalConstants = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalConstants)
	assignment.Vars.LocalWires = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalWires)
	assignment.Constraints = goldilocks.GetGoldilocksExtensionVariableArr(tData.Constraints)
	assignment.GateId = "PublicInputGate"

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal("Error in witness: ", err)
	}

	err = r1cs.IsSolved(witness)
	if err != nil {
		t.Fatal("failed to solve: ", err)
	}

	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BN254))
}

func TestBaseSum(t *testing.T) {
	assert := test.NewAssert(t)

	fileName := "../../../testdata/base_sum_constraints.json"
	fileData, err := os.ReadFile(fileName)
	if err != nil {
		panic(fmt.Sprintln("fail to read file: ", fileName, err))
	}

	var tData TestData

	err = json.Unmarshal(fileData, &tData)
	if err != nil {
		panic(fmt.Sprintln("fail to deserialize: ", err))
	}

	var circuit TestGateCircuit
	circuit.Vars.PublicInputsHash = tData.Vars.PublicInputsHash.GetVariable()
	circuit.Vars.LocalConstants = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalConstants)
	circuit.Vars.LocalWires = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalWires)
	circuit.Constraints = goldilocks.GetGoldilocksExtensionVariableArr(tData.Constraints)
	circuit.GateId = "BaseSumGate { num_limbs: 63 } + Base: 2"

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal("failed to compile: ", err)
	}

	t.Log(r1cs.GetNbConstraints())

	var assignment TestGateCircuit
	assignment.Vars.PublicInputsHash = tData.Vars.PublicInputsHash.GetVariable()
	assignment.Vars.LocalConstants = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalConstants)
	assignment.Vars.LocalWires = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalWires)
	assignment.Constraints = goldilocks.GetGoldilocksExtensionVariableArr(tData.Constraints)
	assignment.GateId = "BaseSumGate { num_limbs: 63 } + Base: 2"

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal("Error in witness: ", err)
	}

	err = r1cs.IsSolved(witness)
	if err != nil {
		t.Fatal("failed to solve: ", err)
	}

	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BN254))
}

func TestExponentiationGate(t *testing.T) {
	assert := test.NewAssert(t)

	fileName := "../../../testdata/exponentiation_constraints.json"
	fileData, err := os.ReadFile(fileName)
	if err != nil {
		panic(fmt.Sprintln("fail to read file: ", fileName, err))
	}

	var tData TestData

	err = json.Unmarshal(fileData, &tData)
	if err != nil {
		panic(fmt.Sprintln("fail to deserialize: ", err))
	}

	var circuit TestGateCircuit
	circuit.Vars.PublicInputsHash = tData.Vars.PublicInputsHash.GetVariable()
	circuit.Vars.LocalConstants = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalConstants)
	circuit.Vars.LocalWires = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalWires)
	circuit.Constraints = goldilocks.GetGoldilocksExtensionVariableArr(tData.Constraints)
	circuit.GateId = "ExponentiationGate { num_power_bits: 17, _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }"

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal("failed to compile: ", err)
	}

	t.Log(r1cs.GetNbConstraints())

	var assignment TestGateCircuit
	assignment.Vars.PublicInputsHash = tData.Vars.PublicInputsHash.GetVariable()
	assignment.Vars.LocalConstants = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalConstants)
	assignment.Vars.LocalWires = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalWires)
	assignment.Constraints = goldilocks.GetGoldilocksExtensionVariableArr(tData.Constraints)
	assignment.GateId = "ExponentiationGate { num_power_bits: 17, _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }"

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal("Error in witness: ", err)
	}

	err = r1cs.IsSolved(witness)
	if err != nil {
		t.Fatal("failed to solve: ", err)
	}

	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BN254))
}

func TestLookupGate(t *testing.T) {
	assert := test.NewAssert(t)

	fileName := "../../../testdata/lookup_constraints.json"
	fileData, err := os.ReadFile(fileName)
	if err != nil {
		panic(fmt.Sprintln("fail to read file: ", fileName, err))
	}

	var tData TestData

	err = json.Unmarshal(fileData, &tData)
	if err != nil {
		panic(fmt.Sprintln("fail to deserialize: ", err))
	}

	var circuit TestGateCircuit
	circuit.Vars.PublicInputsHash = tData.Vars.PublicInputsHash.GetVariable()
	circuit.Vars.LocalConstants = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalConstants)
	circuit.Vars.LocalWires = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalWires)
	circuit.Constraints = goldilocks.GetGoldilocksExtensionVariableArr(tData.Constraints)
	circuit.GateId = "LookupGate {num_slots: 40, lut_hash: [36, 96, 153, 18, 161, 69, 56, 184, 62, 235, 132, 33, 162, 102, 217, 235, 96, 191, 181, 219, 152, 137, 120, 81, 73, 22, 207, 95, 245, 86, 119, 116]}"

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal("failed to compile: ", err)
	}

	t.Log(r1cs.GetNbConstraints())

	var assignment TestGateCircuit
	assignment.Vars.PublicInputsHash = tData.Vars.PublicInputsHash.GetVariable()
	assignment.Vars.LocalConstants = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalConstants)
	assignment.Vars.LocalWires = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalWires)
	assignment.Constraints = goldilocks.GetGoldilocksExtensionVariableArr(tData.Constraints)
	assignment.GateId = "LookupGate {num_slots: 40, lut_hash: [36, 96, 153, 18, 161, 69, 56, 184, 62, 235, 132, 33, 162, 102, 217, 235, 96, 191, 181, 219, 152, 137, 120, 81, 73, 22, 207, 95, 245, 86, 119, 116]}"

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal("Error in witness: ", err)
	}

	err = r1cs.IsSolved(witness)
	if err != nil {
		t.Fatal("failed to solve: ", err)
	}

	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BN254))
}

// TODO: not working
// func TestPoseidonGate(t *testing.T) {
// 	assert := test.NewAssert(t)

// 	fileName := "../../../testdata/poseidon_constraints.json"
// 	fileData, err := os.ReadFile(fileName)
// 	if err != nil {
// 		panic(fmt.Sprintln("fail to read file: ", fileName, err))
// 	}

// 	var tData TestData

// 	err = json.Unmarshal(fileData, &tData)
// 	if err != nil {
// 		panic(fmt.Sprintln("fail to deserialize: ", err))
// 	}

// 	var circuit TestGateCircuit
// 	circuit.Vars.PublicInputsHash = tData.Vars.PublicInputsHash.GetVariable()
// 	circuit.Vars.LocalConstants = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalConstants)
// 	circuit.Vars.LocalWires = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalWires)
// 	circuit.Constraints = goldilocks.GetGoldilocksExtensionVariableArr(tData.Constraints)
// 	circuit.GateId = "PoseidonGate(PhantomData<plonky2_field::goldilocks_field::GoldilocksField>)<WIDTH=12>"

// 	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
// 	if err != nil {
// 		t.Fatal("failed to compile: ", err)
// 	}

// 	t.Log(r1cs.GetNbConstraints())

// 	var assignment TestGateCircuit
// 	assignment.Vars.PublicInputsHash = tData.Vars.PublicInputsHash.GetVariable()
// 	assignment.Vars.LocalConstants = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalConstants)
// 	assignment.Vars.LocalWires = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalWires)
// 	assignment.Constraints = goldilocks.GetGoldilocksExtensionVariableArr(tData.Constraints)
// 	assignment.GateId = "PoseidonGate(PhantomData<plonky2_field::goldilocks_field::GoldilocksField>)<WIDTH=12>"

// 	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
// 	if err != nil {
// 		t.Fatal("Error in witness: ", err)
// 	}

// 	err = r1cs.IsSolved(witness)
// 	if err != nil {
// 		t.Fatal("failed to solve: ", err)
// 	}

// 	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BN254))
// }
