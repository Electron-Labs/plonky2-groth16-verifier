package plonk

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/plonk/gates"
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
	Common_data      types.CommonData `json:"common_data"`
	X                []uint64         `json:"x"`
	Vars             Vars             `json:"vars"`
	Local_zs         [][]uint64       `json:"local_zs"`
	Next_zs          [][]uint64       `json:"next_zs"`
	Local_lookup_zs  [][]uint64       `json:"local_lookup_zs"`
	Next_lookup_zs   [][]uint64       `json:"next_lookup_zs"`
	Partial_products [][]uint64       `json:"partial_products"`
	S_sigmas         [][]uint64       `json:"s_sigmas"`
	Betas            []uint64         `json:"betas"`
	Gammas           []uint64         `json:"gammas"`
	Alphas           []uint64         `json:"alphas"`
	Deltas           []uint64         `json:"deltas"`
	VPZ              [][]uint64       `json:"vanishing_poly_zetas"`
}

type TestVPCircuit struct {
	Common_data      types.CommonData
	X                goldilocks.GoldilocksExtension2Variable
	Vars             gates.EvaluationVars
	Local_zs         []goldilocks.GoldilocksExtension2Variable
	Next_zs          []goldilocks.GoldilocksExtension2Variable
	Local_lookup_zs  []goldilocks.GoldilocksExtension2Variable
	Next_lookup_zs   []goldilocks.GoldilocksExtension2Variable
	Partial_products []goldilocks.GoldilocksExtension2Variable
	S_sigmas         []goldilocks.GoldilocksExtension2Variable
	Betas            []goldilocks.GoldilocksVariable
	Gammas           []goldilocks.GoldilocksVariable
	Alphas           []goldilocks.GoldilocksVariable
	Deltas           []goldilocks.GoldilocksVariable
	VPZ              []goldilocks.GoldilocksExtension2Variable
}

func (circuit *TestVPCircuit) Define(api frontend.API) error {
	rangeChecker := rangecheck.New(api)
	x_pow_deg := goldilocks.ExpPow2Ext(api, rangeChecker, circuit.X, int(circuit.Common_data.FriParams.DegreeBits))
	vpz := EvalVanishingPoly(
		api,
		rangeChecker,
		circuit.Common_data,
		circuit.X,
		x_pow_deg,
		circuit.Vars,
		circuit.Local_zs,
		circuit.Next_zs,
		circuit.Local_lookup_zs,
		circuit.Next_lookup_zs,
		circuit.Partial_products,
		circuit.S_sigmas,
		circuit.Betas,
		circuit.Gammas,
		circuit.Alphas,
		circuit.Deltas,
	)
	for i := range circuit.VPZ {
		api.AssertIsEqual(circuit.VPZ[i].A.Limb, vpz[i].A.Limb)
		api.AssertIsEqual(circuit.VPZ[i].B.Limb, vpz[i].B.Limb)
	}
	return nil
}

func TestVP(t *testing.T) {
	assert := test.NewAssert(t)

	fileName := "../../testdata/vanishing_poly.json"
	fileData, err := os.ReadFile(fileName)
	if err != nil {
		panic(fmt.Sprintln("fail to read file: ", fileName, err))
	}

	var tData TestData

	err = json.Unmarshal(fileData, &tData)
	if err != nil {
		panic(fmt.Sprintln("fail to deserialize: ", err))
	}

	var circuit TestVPCircuit
	circuit.Common_data = tData.Common_data
	circuit.X = goldilocks.GetGoldilocksExtensionVariable(tData.X)
	circuit.Vars.PublicInputsHash = tData.Vars.PublicInputsHash.GetVariable()
	circuit.Vars.LocalConstants = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalConstants)
	circuit.Vars.LocalWires = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalWires)
	circuit.Local_zs = goldilocks.GetGoldilocksExtensionVariableArr(tData.Local_zs)
	circuit.Next_zs = goldilocks.GetGoldilocksExtensionVariableArr(tData.Next_zs)
	circuit.Local_lookup_zs = goldilocks.GetGoldilocksExtensionVariableArr(tData.Local_lookup_zs)
	circuit.Next_lookup_zs = goldilocks.GetGoldilocksExtensionVariableArr(tData.Next_lookup_zs)
	circuit.Partial_products = goldilocks.GetGoldilocksExtensionVariableArr(tData.Partial_products)
	circuit.S_sigmas = goldilocks.GetGoldilocksExtensionVariableArr(tData.S_sigmas)
	circuit.Betas = goldilocks.GetGoldilocksVariableArr(tData.Betas)
	circuit.Gammas = goldilocks.GetGoldilocksVariableArr(tData.Gammas)
	circuit.Alphas = goldilocks.GetGoldilocksVariableArr(tData.Alphas)
	circuit.Deltas = goldilocks.GetGoldilocksVariableArr(tData.Deltas)
	circuit.VPZ = goldilocks.GetGoldilocksExtensionVariableArr(tData.VPZ)

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal("failed to compile: ", err)
	}

	t.Log(r1cs.GetNbConstraints())

	var assignment TestVPCircuit
	assignment.Common_data = tData.Common_data
	assignment.X = goldilocks.GetGoldilocksExtensionVariable(tData.X)
	assignment.Vars.PublicInputsHash = tData.Vars.PublicInputsHash.GetVariable()
	assignment.Vars.LocalConstants = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalConstants)
	assignment.Vars.LocalWires = goldilocks.GetGoldilocksExtensionVariableArr(tData.Vars.LocalWires)
	assignment.Local_zs = goldilocks.GetGoldilocksExtensionVariableArr(tData.Local_zs)
	assignment.Next_zs = goldilocks.GetGoldilocksExtensionVariableArr(tData.Next_zs)
	assignment.Local_lookup_zs = goldilocks.GetGoldilocksExtensionVariableArr(tData.Local_lookup_zs)
	assignment.Next_lookup_zs = goldilocks.GetGoldilocksExtensionVariableArr(tData.Next_lookup_zs)
	assignment.Partial_products = goldilocks.GetGoldilocksExtensionVariableArr(tData.Partial_products)
	assignment.S_sigmas = goldilocks.GetGoldilocksExtensionVariableArr(tData.S_sigmas)
	assignment.Betas = goldilocks.GetGoldilocksVariableArr(tData.Betas)
	assignment.Gammas = goldilocks.GetGoldilocksVariableArr(tData.Gammas)
	assignment.Alphas = goldilocks.GetGoldilocksVariableArr(tData.Alphas)
	assignment.Deltas = goldilocks.GetGoldilocksVariableArr(tData.Deltas)
	assignment.VPZ = goldilocks.GetGoldilocksExtensionVariableArr(tData.VPZ)

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
