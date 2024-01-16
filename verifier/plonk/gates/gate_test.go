package gates

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/types"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/consensys/gnark/test"
)

type Vars struct {
	LocalConstants   [][]uint64                          `json:"local_constants"`
	LocalWires       [][]uint64                          `json:"local_wires"`
	PublicInputsHash types.PoseidonGoldilocksHashOutType `json:"public_inputs_hash"`
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

func CheckGate(fileName string, gateId string, t *testing.T) {
	assert := test.NewAssert(t)

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
	circuit.GateId = gateId

	// TODO:
	// r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	// if err != nil {
	// 	t.Fatal("failed to compile: ", err)
	// }
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	r1cs := ccs.(*cs.SparseR1CS)
	// scs := r1cs.(*cs.SparseR1CS)
	// srs, err := test.NewKZGSRS(scs)
	// srs, err := kzg_bn254.NewSRS(uint64(math.Pow(2, 28)), big.NewInt(-1))

	t.Log(r1cs.GetNbConstraints())

	var assignment TestGateCircuit
	assignment.Vars.PublicInputsHash = tData.Vars.PublicInputsHash.GetVariable()
	assignment.Vars.LocalConstants = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalConstants)
	assignment.Vars.LocalWires = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalWires)
	assignment.Constraints = goldilocks.GetGoldilocksExtensionVariableArr(tData.Constraints)
	assignment.GateId = gateId

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal("Error in witness: ", err)
	}

	err = r1cs.IsSolved(witness)
	if err != nil {
		t.Fatal("failed to solve: ", err)
	}

	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BN254), test.WithBackends(backend.PLONK))
}

func TestArithmeticGate(t *testing.T) {
	CheckGate(
		"../../../testdata/airthmetic_constraints.json",
		"ArithmeticGate { num_ops: 20 }",
		t,
	)
}

func TestArithmeticExtensionGate(t *testing.T) {
	CheckGate(
		"../../../testdata/arithmetic_extension_constraints.json",
		"ArithmeticExtensionGate { num_ops: 10 }",
		t,
	)
}

func TestCosetInterpolationGate(t *testing.T) {
	CheckGate(
		"../../../testdata/coset_interpolation_constraints.json",
		"CosetInterpolationGate { subgroup_bits: 4, degree: 6, barycentric_weights: [17293822565076172801, 18374686475376656385, 18446744069413535745, 281474976645120, 17592186044416, 256, 18446744000695107601, 18446744065119617025, 1152921504338411520, 72057594037927936, 1048576, 18446462594437939201, 18446726477228539905, 18446744069414584065, 68719476720, 4294967296], _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>",
		t,
	)
}

func TestConstantGate(t *testing.T) {
	CheckGate(
		"../../../testdata/constant_constraints.json",
		"ConstantGate { num_consts: 2 }",
		t,
	)
}

func TestPublicInputGate(t *testing.T) {
	CheckGate(
		"../../../testdata/public_input_constraints.json",
		"PublicInputGate",
		t,
	)
}

func TestBaseSum(t *testing.T) {
	CheckGate(
		"../../../testdata/base_sum_constraints.json",
		"BaseSumGate { num_limbs: 63 } + Base: 2",
		t,
	)
}

func TestExponentiationGate(t *testing.T) {
	CheckGate(
		"../../../testdata/exponentiation_constraints.json",
		"ExponentiationGate { num_power_bits: 17, _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }",
		t,
	)
}

func TestLookupGate(t *testing.T) {
	CheckGate(
		"../../../testdata/lookup_constraints.json",
		"LookupGate {num_slots: 40, lut_hash: [36, 96, 153, 18, 161, 69, 56, 184, 62, 235, 132, 33, 162, 102, 217, 235, 96, 191, 181, 219, 152, 137, 120, 81, 73, 22, 207, 95, 245, 86, 119, 116]}",
		t,
	)
}

func TestLookupTableGate(t *testing.T) {
	CheckGate(
		"../../../testdata/lookup_table_constraints.json",
		"LookupTableGate {num_slots: 26, lut_hash: [36, 96, 153, 18, 161, 69, 56, 184, 62, 235, 132, 33, 162, 102, 217, 235, 96, 191, 181, 219, 152, 137, 120, 81, 73, 22, 207, 95, 245, 86, 119, 116], last_lut_row: 3}",
		t,
	)
}

func TestMulExtensionGate(t *testing.T) {
	CheckGate(
		"../../../testdata/mul_extension_constraints.json",
		"MulExtensionGate { num_ops: 13 }",
		t,
	)
}

func TestNoopGate(t *testing.T) {
	CheckGate(
		"../../../testdata/noop_constraints.json",
		"NoopGate",
		t,
	)
}

func TestRandomAccessGate(t *testing.T) {
	CheckGate(
		"../../../testdata/random_access_constraints.json",
		"RandomAccessGate { bits: 4, num_copies: 4, num_extra_constants: 2, _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>",
		t,
	)
}

func TestReducingGate(t *testing.T) {
	CheckGate(
		"../../../testdata/reducing_constraints.json",
		"ReducingGate { num_coeffs: 43 }",
		t,
	)
}

func TestReducingExtensionGate(t *testing.T) {
	CheckGate(
		"../../../testdata/reducing_extension_constraints.json",
		"ReducingExtensionGate { num_coeffs: 32 }",
		t,
	)
}

func TestPoseidonMdsGate(t *testing.T) {
	CheckGate(
		"../../../testdata/poseidon_mds_constraints.json",
		"PoseidonMdsGate(PhantomData<plonky2_field::goldilocks_field::GoldilocksField>)",
		t,
	)
}

func TestU32ComparisonGate(t *testing.T) {
	CheckGate(
		"../../../testdata/u32_comparison_constraints.json",
		"ComparisonGate { num_bits: 32, num_chunks: 16, _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>",
		t,
	)
}

func TestU32AddMany(t *testing.T) {
	CheckGate(
		"../../../testdata/u32_add_many_constraints.json",
		"U32AddManyGate { num_addends: 2, num_ops: 5, _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }",
		t,
	)
}

func TestU32Arithmetic(t *testing.T) {
	CheckGate(
		"../../../testdata/u32_arithmetic_constraints.json",
		"U32ArithmeticGate { num_ops: 3, _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }",
		t,
	)
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
