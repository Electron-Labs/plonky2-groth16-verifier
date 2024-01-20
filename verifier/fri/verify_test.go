package fri

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/types"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
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
	circuit.Proof.PlonkZsPartialProductsCap = make(types.MerkleCapVariable, len(proof.WiresCap))
	circuit.Proof.QuotientPolysCap = make(types.MerkleCapVariable, len(proof.WiresCap))

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
	}

	circuit.Proof.OpeningProof.QueryRoundProofs = make([]types.FriQueryRoundVariable, len(proof.OpeningProof.QueryRoundProofs))
	// num_evals := []uint64{constants.NUM_EVALS_1, constants.NUM_EVALS_2, constants.NUM_EVALS_3, constants.NUM_EVALS_4}
	for i := range circuit.Proof.OpeningProof.QueryRoundProofs {
		circuit.Proof.OpeningProof.QueryRoundProofs[i].InitialTreeProof.EvalsProofs = make([]types.EvalProofVariable, len(proof.OpeningProof.QueryRoundProofs[i].InitialTreeProof.EvalsProofs))
		for j := range circuit.Proof.OpeningProof.QueryRoundProofs[i].InitialTreeProof.EvalsProofs {
			circuit.Proof.OpeningProof.QueryRoundProofs[i].InitialTreeProof.EvalsProofs[j].X = make([]goldilocks.GoldilocksVariable, len(proof.OpeningProof.QueryRoundProofs[i].InitialTreeProof.EvalsProofs[j].X))
			circuit.Proof.OpeningProof.QueryRoundProofs[i].InitialTreeProof.EvalsProofs[j].Y.Siblings = make([]types.PoseidonBn254HashOut, len(proof.OpeningProof.QueryRoundProofs[i].InitialTreeProof.EvalsProofs[j].Y.Siblings))
		}

		circuit.Proof.OpeningProof.QueryRoundProofs[i].Steps = make([]types.FriQueryStepVariable, len(proof.OpeningProof.QueryRoundProofs[i].Steps))
		for j := range circuit.Proof.OpeningProof.QueryRoundProofs[i].Steps {
			circuit.Proof.OpeningProof.QueryRoundProofs[i].Steps[j].Evals = make([]goldilocks.GoldilocksExtension2Variable, len(proof.OpeningProof.QueryRoundProofs[i].Steps[j].Evals))
			circuit.Proof.OpeningProof.QueryRoundProofs[i].Steps[j].MerkleProof.Siblings = make([]types.PoseidonBn254HashOut, len(proof.OpeningProof.QueryRoundProofs[i].Steps[j].MerkleProof.Siblings))
		}
	}

	circuit.Proof.OpeningProof.FinalPoly.Coeffs = make([]goldilocks.GoldilocksExtension2Variable, len(proof.OpeningProof.FinalPoly.Coeffs))

	circuit.VerifierData.ConstantSigmasCap = make(types.MerkleCapVariable, len(proof.WiresCap))

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

	commonData, err := read_common_data_from_file("../../testdata/verify_fri/common_data.json")
	if err != nil {
		t.Fatal("Error in common data")
	}
	proof, err := read_proof_from_file("../../testdata/verify_fri/proof_with_pis.json")
	if err != nil {
		t.Fatal("Error in reading proof")
	}
	verifierData, err := read_verifier_data_from_file("../../testdata/verify_fri/verifier_only.json")
	if err != nil {
		t.Fatal("Error in verifier data")
	}
	proof_var := proof.GetVariable()
	verifier_data_var := verifierData.GetVariable()

	// for goldilocks/poseidon_bn254 data
	zeta := goldilocks.GetGoldilocksExtensionVariable([]uint64{16263632293919212639, 10013997701259715621})
	fri_alpha := goldilocks.GetGoldilocksExtensionVariable([]uint64{13172871457756936397, 1804723272509206341})
	fri_betas := goldilocks.GetGoldilocksExtensionVariableArr([][]uint64{
		{5393533806932209970, 10643556356350979542},
	})
	fri_pow_response := goldilocks.GetGoldilocksVariable(60661718710665)
	fri_query_indices := []frontend.Variable{486, 33, 62, 251, 123, 391, 447, 94, 477, 56, 123, 360, 365, 292, 228, 373, 92, 408, 379, 92, 231, 314, 370, 54, 503, 220, 393, 80}

	// for tendermint data
	// zeta := goldilocks.GetGoldilocksExtensionVariable([]uint64{15457524938562325708, 3479679977809551659})
	// fri_alpha := goldilocks.GetGoldilocksExtensionVariable([]uint64{9846366809370789810, 11042981004784868283})
	// fri_betas := goldilocks.GetGoldilocksExtensionVariableArr([][]uint64{
	// 	{18250851304787470475, 5971507749560382253},
	// 	{5205581278872883023, 15850745646177162614},
	// 	{5448555762200760647, 8279983161807516452},
	// })
	// fri_pow_response := goldilocks.GetGoldilocksVariable(10666470807687)
	// fri_query_indices := []frontend.Variable{165941, 193126, 290810, 374631, 420056, 398992, 99294, 70377, 271757, 187131, 6270, 112428, 350692, 334230, 513975, 34774, 214484, 357427, 271777, 438693, 252239, 63737, 161872, 275441, 75160, 302773, 385283, 148460}

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

	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BN254), test.WithBackends(backend.PLONK))

}
