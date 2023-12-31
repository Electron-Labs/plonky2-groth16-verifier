package fri

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/types"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/consensys/gnark/test"
)

type VerifyFriTest struct {
	Zeta          goldilocks.GoldilocksExtension2Variable
	CommonData    types.CommonData
	Proof         types.ProofVariable
	VerifierData  types.VerifierOnlyVariable
	FriChallenges types.FriChallengesVariable
}

func (circuit *VerifyFriTest) Define(api frontend.API) error {
	rangeChecker := rangecheck.New(api)
	merkle_caps := []types.MerkleCapVariable{
		circuit.VerifierData.ConstantSigmasCap,
		circuit.Proof.WiresCap,
		circuit.Proof.PlonkZsPartialProductsCap,
		circuit.Proof.QuotientPolysCap,
	}
	VerifyFriProof(
		api,
		rangeChecker,
		GetFriInstance(api, rangeChecker, circuit.CommonData, circuit.Zeta),
		GetFriOpenings(circuit.Proof.Openings),
		circuit.FriChallenges,
		merkle_caps,
		circuit.Proof.OpeningProof,
		circuit.CommonData.FriParams,
	)
	return nil
}

func (circuit *VerifyFriTest) Make(proof types.ProofVariable, fri_challenges types.FriChallengesVariable, commonData types.CommonData) {
	circuit.CommonData = commonData
	circuit.Proof.WiresCap = make(types.MerkleCapVariable, len(proof.WiresCap))
	for i := range circuit.Proof.WiresCap {
		circuit.Proof.WiresCap[i].Make()
	}
	circuit.Proof.PlonkZsPartialProductsCap = make(types.MerkleCapVariable, len(proof.WiresCap))
	for i := range circuit.Proof.PlonkZsPartialProductsCap {
		circuit.Proof.PlonkZsPartialProductsCap[i].Make()
	}
	circuit.Proof.QuotientPolysCap = make(types.MerkleCapVariable, len(proof.WiresCap))
	for i := range circuit.Proof.QuotientPolysCap {
		circuit.Proof.QuotientPolysCap[i].Make()
	}

	circuit.Proof.Openings.Constants = make([]goldilocks.GoldilocksExtension2Variable, len(proof.Openings.Constants))
	circuit.Proof.Openings.PlonkSigmas = make([]goldilocks.GoldilocksExtension2Variable, len(proof.Openings.PlonkSigmas))
	circuit.Proof.Openings.Wires = make([]goldilocks.GoldilocksExtension2Variable, len(proof.Openings.Wires))
	circuit.Proof.Openings.PlonkZs = make([]goldilocks.GoldilocksExtension2Variable, len(proof.Openings.PlonkZs))
	circuit.Proof.Openings.PlonkZsNext = make([]goldilocks.GoldilocksExtension2Variable, len(proof.Openings.PlonkZsNext))
	circuit.Proof.Openings.PartialProducts = make([]goldilocks.GoldilocksExtension2Variable, len(proof.Openings.PartialProducts))
	circuit.Proof.Openings.QuotientPolys = make([]goldilocks.GoldilocksExtension2Variable, len(proof.Openings.QuotientPolys))
	circuit.Proof.Openings.LookupZs = make([]goldilocks.GoldilocksExtension2Variable, len(proof.Openings.LookupZs))
	circuit.Proof.Openings.LookupZsNext = make([]goldilocks.GoldilocksExtension2Variable, len(proof.Openings.LookupZsNext))

	circuit.Proof.OpeningProof.CommitPhaseMerkleCap = make([]types.MerkleCapVariable, len(proof.OpeningProof.CommitPhaseMerkleCap))
	for i := range circuit.Proof.OpeningProof.CommitPhaseMerkleCap {
		circuit.Proof.OpeningProof.CommitPhaseMerkleCap[i] = make(types.MerkleCapVariable, len(proof.WiresCap))
		for j := range circuit.Proof.OpeningProof.CommitPhaseMerkleCap[i] {
			circuit.Proof.OpeningProof.CommitPhaseMerkleCap[i][j].Make()
		}
	}

	circuit.Proof.OpeningProof.QueryRoundProofs = make([]types.FriQueryRoundVariable, len(proof.OpeningProof.QueryRoundProofs))
	// num_evals := []uint64{constants.NUM_EVALS_1, constants.NUM_EVALS_2, constants.NUM_EVALS_3, constants.NUM_EVALS_4}
	for i := range circuit.Proof.OpeningProof.QueryRoundProofs {
		circuit.Proof.OpeningProof.QueryRoundProofs[i].InitialTreeProof.EvalsProofs = make([]types.EvalProofVariable, len(proof.OpeningProof.QueryRoundProofs[i].InitialTreeProof.EvalsProofs))
		for j := range circuit.Proof.OpeningProof.QueryRoundProofs[i].InitialTreeProof.EvalsProofs {
			circuit.Proof.OpeningProof.QueryRoundProofs[i].InitialTreeProof.EvalsProofs[j].X = make([]goldilocks.GoldilocksVariable, len(proof.OpeningProof.QueryRoundProofs[i].InitialTreeProof.EvalsProofs[j].X))
			circuit.Proof.OpeningProof.QueryRoundProofs[i].InitialTreeProof.EvalsProofs[j].Y.Siblings = make([]types.HashOutVariable, len(proof.OpeningProof.QueryRoundProofs[i].InitialTreeProof.EvalsProofs[j].Y.Siblings))
			for k := range circuit.Proof.OpeningProof.QueryRoundProofs[i].InitialTreeProof.EvalsProofs[j].Y.Siblings {
				circuit.Proof.OpeningProof.QueryRoundProofs[i].InitialTreeProof.EvalsProofs[j].Y.Siblings[k].Make()
			}
		}

		circuit.Proof.OpeningProof.QueryRoundProofs[i].Steps = make([]types.FriQueryStepVariable, len(proof.OpeningProof.QueryRoundProofs[i].Steps))
		for j := range circuit.Proof.OpeningProof.QueryRoundProofs[i].Steps {
			circuit.Proof.OpeningProof.QueryRoundProofs[i].Steps[j].Evals = make([]goldilocks.GoldilocksExtension2Variable, len(proof.OpeningProof.QueryRoundProofs[i].Steps[j].Evals))
			circuit.Proof.OpeningProof.QueryRoundProofs[i].Steps[j].MerkleProof.Siblings = make([]types.HashOutVariable, len(proof.OpeningProof.QueryRoundProofs[i].Steps[j].MerkleProof.Siblings))
			for k := range circuit.Proof.OpeningProof.QueryRoundProofs[i].Steps[j].MerkleProof.Siblings {
				circuit.Proof.OpeningProof.QueryRoundProofs[i].Steps[j].MerkleProof.Siblings[k].Make()
			}
		}
	}

	circuit.Proof.OpeningProof.FinalPoly.Coeffs = make([]goldilocks.GoldilocksExtension2Variable, len(proof.OpeningProof.FinalPoly.Coeffs))

	circuit.VerifierData.ConstantSigmasCap = make(types.MerkleCapVariable, len(proof.WiresCap))
	for i := range circuit.VerifierData.ConstantSigmasCap {
		circuit.VerifierData.ConstantSigmasCap[i].Make()
	}
	circuit.VerifierData.CircuitDigest.Make()

	circuit.FriChallenges.FriBetas = make([]goldilocks.GoldilocksExtension2Variable, len(fri_challenges.FriBetas))
	circuit.FriChallenges.FriQueryIndices = make([]frontend.Variable, len(fri_challenges.FriQueryIndices))

}

func read_proof_from_file(path string) (types.Proof, error) {
	jsonProofData, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println("Error reading verifier only json file:", err)
		return types.Proof{}, err
	}
	var proof types.Proof
	if err := json.Unmarshal(jsonProofData, &proof); err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return types.Proof{}, err
	}
	return proof, nil
}

func read_common_data_from_file(path string) (types.CommonData, error) {
	jsonCommonData, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println("Error reading JSON file:", err)
		return types.CommonData{}, err
	}

	var commonData types.CommonData

	if err := json.Unmarshal(jsonCommonData, &commonData); err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return types.CommonData{}, err
	}
	return commonData, nil
}

func read_verifier_data_from_file(path string) (types.VerifierOnly, error) {
	jsonVerifierData, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println("Error reading verifier only json file:", err)
		return types.VerifierOnly{}, err
	}
	var verifier_only types.VerifierOnly
	if err := json.Unmarshal(jsonVerifierData, &verifier_only); err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return types.VerifierOnly{}, err
	}
	return verifier_only, nil
}

func TestVerifyFri(t *testing.T) {
	assert := test.NewAssert(t)

	commonData, err := read_common_data_from_file("../../data/goldilocks/common_data.json")
	if err != nil {
		t.Fatal("Error in common data")
	}
	proof, err := read_proof_from_file("../../data/goldilocks/proof_with_pis.json")
	if err != nil {
		t.Fatal("Error in reading proof")
	}
	verifierData, err := read_verifier_data_from_file("../../data/goldilocks/verifier_only.json")
	if err != nil {
		t.Fatal("Error in verifier data")
	}
	proof_var := proof.GetVariable()
	verifier_data_var := verifierData.GetVariable()
	zeta := goldilocks.GetGoldilocksExtensionVariable([]uint64{6433831523151700796, 16638450956802163867})
	fri_alpha := goldilocks.GetGoldilocksExtensionVariable([]uint64{3382174530905268205, 2495127857901811513})
	fri_betas := goldilocks.GetGoldilocksExtensionVariableArr([][]uint64{
		{1828208506809751845, 8202965097133682349},
		{1197028379089443624, 170112253994851017},
	})
	fri_pow_response := goldilocks.GetGoldilocksVariable(257134902485115)
	fri_query_indices := []frontend.Variable{13, 20, 15, 2, 15, 11, 30, 23, 17, 24, 30, 7, 23, 27, 22, 23, 10, 29, 9, 6, 5, 25, 4, 27, 22, 16, 31, 26}

	fri_challenges := types.FriChallengesVariable{
		FriAlpha:        fri_alpha,
		FriBetas:        fri_betas,
		FriPowResponse:  fri_pow_response,
		FriQueryIndices: fri_query_indices,
	}

	var circuit VerifyFriTest
	circuit.Make(proof_var, fri_challenges, commonData)

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal("failed to compile: ", err)
	}
	t.Log(r1cs.GetNbConstraints())

	var assignment VerifyFriTest
	assignment.CommonData = commonData
	assignment.Proof = proof_var
	assignment.VerifierData = verifier_data_var
	assignment.FriChallenges = fri_challenges
	assignment.Zeta = zeta

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
