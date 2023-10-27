package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"os"

	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier"
)

func read_common_data_from_file(path string) (verifier.CommonData, error) {
	jsonCommonData, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println("Error reading JSON file:", err)
		return verifier.CommonData{}, err
	}

	var commonData verifier.CommonData

	if err := json.Unmarshal(jsonCommonData, &commonData); err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return verifier.CommonData{}, err
	}
	return commonData, nil
}

func read_verifier_data_from_file(path string) (verifier.VerifierOnly, error) {
	jsonVerifierData, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println("Error reading verifier only json file:", err)
		return verifier.VerifierOnly{}, err
	}
	var verifier_only verifier.VerifierOnly
	if err := json.Unmarshal(jsonVerifierData, &verifier_only); err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return verifier.VerifierOnly{}, err
	}
	return verifier_only, nil
}

func read_proof_from_file(path string) (verifier.Proof, error) {
	jsonProofData, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println("Error reading verifier only json file:", err)
		return verifier.Proof{}, err
	}
	var proof verifier.Proof
	if err := json.Unmarshal(jsonProofData, &proof); err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return verifier.Proof{}, err
	}
	return proof, nil
}

func read_public_inputs_from_file(path string) (verifier.PublicInputs, error) {
	jsonPublicInputsData, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println("Error reading verifier only json file:", err)
		return verifier.PublicInputs{}, err
	}
	var pub_inputs verifier.PublicInputs
	if err := json.Unmarshal(jsonPublicInputsData, &pub_inputs); err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return verifier.PublicInputs{}, err
	}
	return pub_inputs, nil
}

func dummy(proof_path string, verifier_only_path string, common_data_path string, pub_input_path string) {
	var proof verifier.Proof
	var verifier_only verifier.VerifierOnly
	var common_data verifier.CommonData
	var pub_inputs verifier.PublicInputs
	jsonProofData, _ := ioutil.ReadFile(proof_path)
	if err := json.Unmarshal(jsonProofData, &proof); err != nil {
		fmt.Println("Error unmarshaling JSON1:", err)
		os.Exit(1)
	}
	jsonVerifierOnlyData, _ := ioutil.ReadFile(verifier_only_path)
	if err := json.Unmarshal(jsonVerifierOnlyData, &verifier_only); err != nil {
		fmt.Println("Error unmarshaling JSON2:", err)
		os.Exit(1)
	}
	jsonCommonData, _ := ioutil.ReadFile(common_data_path)
	if err := json.Unmarshal(jsonCommonData, &common_data); err != nil {
		fmt.Println("Error unmarshaling JSON3:", err)
		os.Exit(1)
	}
	jsonPublicInputsData, _ := ioutil.ReadFile(pub_input_path)
	if err := json.Unmarshal(jsonPublicInputsData, &pub_inputs); err != nil {
		fmt.Println("Error unmarshaling JSON4:", err)
		os.Exit(1)
	}
	// CAP_LEN
	println(len(proof.WiresCap) == int(math.Pow(2, float64(common_data.FriParams.Config.CapHeight))))
	println(len(proof.PlonkZsPartialProductsCap) == int(math.Pow(2, float64(common_data.FriParams.Config.CapHeight))))
	println(len(proof.QuotientPolysCap) == int(math.Pow(2, float64(common_data.FriParams.Config.CapHeight))))
	opening_set := proof.Openings
	// CONSTANTS
	println(len(opening_set.Constants) == int(common_data.NumConstants))
	// PLONK_SIGMAS
	println(len(opening_set.PlonkSigmas) == int(common_data.Config.NumRoutedWires))
	// WIRES
	println(len(opening_set.Wires) == int(common_data.Config.NumWires))
	// PLONK_ZS
	println(len(opening_set.PlonkZs) == int(common_data.Config.NumChallenges))
	println(len(opening_set.PlonkZsNext) == int(common_data.Config.NumChallenges))
	// PARTIAL_PRODUCTS
	println(len(opening_set.PartialProducts) == int(common_data.Config.NumChallenges*common_data.NumPartialProducts))
	// QUOTIENT_POLYS
	println(len(opening_set.QuotientPolys) == int(common_data.Config.NumChallenges*common_data.QuotientDegreeFactor))
	// LOOKUP_ZS
	println(len(opening_set.LookupZs) == int(common_data.Config.NumChallenges*common_data.NumLookupPolys))
	println(len(opening_set.LookupZsNext) == int(common_data.Config.NumChallenges*common_data.NumLookupPolys))
	opening_proof := proof.OpeningProof
	// COMMIT_PHASE_MERKLE_CAPS
	println(len(opening_proof.CommitPhaseMerkleCap) == len(common_data.FriParams.ReductionArityBits))
	println(len(opening_proof.CommitPhaseMerkleCap[0]) == int(math.Pow(2, float64(common_data.FriParams.Config.CapHeight))))
	// NUM_QUERY_ROUNDS
	println(len(opening_proof.QueryRoundProofs) == int(common_data.FriParams.Config.NumQueryRounds))
	// NUM_INITIAL_EVAL_PROOFS = 4
	println(len(opening_proof.QueryRoundProofs[0].InitialTreeProof.EvalsProofs) == 4)

	// NUM_EVALS_1
	s1 := common_data.NumConstants + common_data.Config.NumRoutedWires
	println(len(opening_proof.QueryRoundProofs[0].InitialTreeProof.EvalsProofs[0].X) == int(s1))

	// NUM_EVALS_2
	s2 := common_data.Config.NumWires
	println(len(opening_proof.QueryRoundProofs[0].InitialTreeProof.EvalsProofs[1].X) == int(s2))

	// NUM_EVALS_3
	s3 := common_data.Config.NumChallenges * (1 + common_data.NumPartialProducts + common_data.NumLookupPolys)
	println(len(opening_proof.QueryRoundProofs[0].InitialTreeProof.EvalsProofs[2].X) == int(s3))

	// NUM_EVALS_4
	s4 := common_data.Config.NumChallenges * common_data.QuotientDegreeFactor
	println(len(opening_proof.QueryRoundProofs[0].InitialTreeProof.EvalsProofs[3].X) == int(s4))

	// INITIAL_EVAL_PROOF_SIBLINGS
	println(len(opening_proof.QueryRoundProofs[0].InitialTreeProof.EvalsProofs[0].Y.Siblings) == int(common_data.FriParams.DegreeBits+common_data.Config.FriConfig.RateBits-common_data.FriParams.Config.CapHeight))
	// NUM_STEPS
	println(len(opening_proof.QueryRoundProofs[0].Steps) == len(common_data.FriParams.ReductionArityBits))
	// STEPS = [siblings_len_for_each_level (0..NUM_STEPS)]
	println(len(opening_proof.QueryRoundProofs[0].Steps[0].Evals) == (1 << common_data.FriParams.ReductionArityBits[0]))
	total_len_tree := common_data.FriParams.DegreeBits + common_data.Config.FriConfig.RateBits - common_data.FriParams.Config.CapHeight
	siblings := total_len_tree - common_data.FriParams.ReductionArityBits[0]
	println(int(siblings) == len(opening_proof.QueryRoundProofs[0].Steps[0].MerkleProof.Siblings))
	sum := uint64(0)
	for _, num := range common_data.FriParams.ReductionArityBits {
		sum += num
	}
	// FINAL_POLY_COEFFS
	println(len(opening_proof.FinalPoly.Coeffs) == (1 << int(common_data.FriParams.DegreeBits-sum)))

}
