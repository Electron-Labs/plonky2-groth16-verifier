package cmd

import (
	"encoding/json"
	"fmt"
	"math"
	"os"

	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/types"
)

func ReadCommonDataFromFile(path string) (types.CommonData, error) {
	jsonCommonData, err := os.ReadFile(path)
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

func ReadVerifierDataFromFile(path string) (types.VerifierOnly, error) {
	jsonVerifierData, err := os.ReadFile(path)
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

func ReadProofFromFile(path string) (types.Proof, error) {
	jsonProofData, err := os.ReadFile(path)
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

func ReadPlonky2PublicInputsFromFile(path string) (types.Plonky2PublicInputs, error) {
	jsonPublicInputsData, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("Error reading verifier only json file:", err)
		return types.Plonky2PublicInputs{}, err
	}
	var pub_inputs types.Plonky2PublicInputs
	if err := json.Unmarshal(jsonPublicInputsData, &pub_inputs); err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return types.Plonky2PublicInputs{}, err
	}
	return pub_inputs, nil
}

func ReadGnarkPublicInputsFromFile(path string) (types.GnarkPublicInputs, error) {
	jsonPublicInputsData, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("Error reading verifier only json file:", err)
		return types.GnarkPublicInputs{}, err
	}
	var pubInputs types.GnarkPublicInputs
	if err := json.Unmarshal(jsonPublicInputsData, &pubInputs); err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return types.GnarkPublicInputs{}, err
	}
	return pubInputs, nil
}

func GetCircuitConstants(common_data types.CommonData) verifier.CircuitConstants {

	s1 := common_data.NumConstants + common_data.Config.NumRoutedWires

	// NUM_EVALS_2
	s2 := common_data.Config.NumWires

	// NUM_EVALS_3
	s3 := common_data.Config.NumChallenges * (1 + common_data.NumPartialProducts + common_data.NumLookupPolys)

	// NUM_EVALS_4
	s4 := common_data.Config.NumChallenges * common_data.QuotientDegreeFactor
	total_len_tree := common_data.FriParams.DegreeBits + common_data.Config.FriConfig.RateBits - common_data.FriParams.Config.CapHeight
	var evals []uint64
	var siblings []uint64
	for i, bit := range common_data.FriParams.ReductionArityBits {
		if i == 0 {
			siblings = append(siblings, total_len_tree-common_data.FriParams.ReductionArityBits[i])
		} else {
			siblings = append(siblings, siblings[i-1]-common_data.FriParams.ReductionArityBits[i])
		}
		evals = append(evals, 1<<bit)
	}
	sum := uint64(0)
	for _, num := range common_data.FriParams.ReductionArityBits {
		sum += num
	}
	return verifier.CircuitConstants{
		CAP_LEN:                     uint64((math.Pow(2, float64(common_data.FriParams.Config.CapHeight)))),
		CONSTANTS:                   uint64(common_data.NumConstants),
		PLONK_SIGMAS:                uint64(common_data.Config.NumRoutedWires),
		WIRES:                       uint64(common_data.Config.NumWires),
		PLONK_ZS:                    uint64(common_data.Config.NumChallenges),
		PARTIAL_PRODUCTS:            uint64(common_data.Config.NumChallenges * common_data.NumPartialProducts),
		QUOTIENT_POLYS:              uint64(common_data.Config.NumChallenges * common_data.QuotientDegreeFactor),
		LOOKUP_ZS:                   uint64(common_data.Config.NumChallenges * common_data.NumLookupPolys),
		COMMIT_PHASE_MERKLE_CAPS:    uint64(len(common_data.FriParams.ReductionArityBits)),
		NUM_QUERY_ROUNDS:            uint64(common_data.FriParams.Config.NumQueryRounds),
		NUM_INITIAL_EVAL_PROOFS:     uint64(4),
		NUM_EVALS_1:                 s1,
		NUM_EVALS_2:                 s2,
		NUM_EVALS_3:                 s3,
		NUM_EVALS_4:                 s4,
		INITIAL_EVAL_PROOF_SIBLINGS: uint64(common_data.FriParams.DegreeBits + common_data.Config.FriConfig.RateBits - common_data.FriParams.Config.CapHeight),
		NUM_STEPS:                   uint64(len(common_data.FriParams.ReductionArityBits)),
		LEVEL_EVALS:                 evals,
		LEVEL_SIBLINGS:              siblings,
		FINAL_POLY_COEFFS:           uint64((1 << int(common_data.FriParams.DegreeBits-sum))),
		NUM_PLONKY2_PUBLIC_INPUTS:   common_data.NumPublicInputs,
		NUM_GNARK_PUBLIC_INPUTS:     common_data.NumPublicInputs/8 - 1 + 2,
	}
}

// println(len(proof.WiresCap) == int(math.Pow(2, float64(common_data.FriParams.Config.CapHeight))))
// println(len(proof.PlonkZsPartialProductsCap) == int(math.Pow(2, float64(common_data.FriParams.Config.CapHeight))))
// println(len(proof.QuotientPolysCap) == int(math.Pow(2, float64(common_data.FriParams.Config.CapHeight))))
// opening_set := proof.Openings
// // CONSTANTS
// println(len(opening_set.Constants) == int(common_data.NumConstants))
// // PLONK_SIGMAS
// println(len(opening_set.PlonkSigmas) == int(common_data.Config.NumRoutedWires))
// // WIRES
// println(len(opening_set.Wires) == int(common_data.Config.NumWires))
// // PLONK_ZS
// println(len(opening_set.PlonkZs) == int(common_data.Config.NumChallenges))
// println(len(opening_set.PlonkZsNext) == int(common_data.Config.NumChallenges))
// // PARTIAL_PRODUCTS
// println(len(opening_set.PartialProducts) == int(common_data.Config.NumChallenges*common_data.NumPartialProducts))
// // QUOTIENT_POLYS
// println(len(opening_set.QuotientPolys) == int(common_data.Config.NumChallenges*common_data.QuotientDegreeFactor))
// // LOOKUP_ZS
// println(len(opening_set.LookupZs) == int(common_data.Config.NumChallenges*common_data.NumLookupPolys))
// println(len(opening_set.LookupZsNext) == int(common_data.Config.NumChallenges*common_data.NumLookupPolys))
// // COMMIT_PHASE_MERKLE_CAPS
// println(len(opening_proof.CommitPhaseMerkleCap) == len(common_data.FriParams.ReductionArityBits))
// println(len(opening_proof.CommitPhaseMerkleCap[0]) == int(math.Pow(2, float64(common_data.FriParams.Config.CapHeight))))
// // NUM_QUERY_ROUNDS
// println(len(opening_proof.QueryRoundProofs) == int(common_data.FriParams.Config.NumQueryRounds))
// // NUM_INITIAL_EVAL_PROOFS = 4
// println(len(opening_proof.QueryRoundProofs[0].InitialTreeProof.EvalsProofs) == 4)

// // // NUM_EVALS_1
// // s1 := common_data.NumConstants + common_data.Config.NumRoutedWires
// // println(len(opening_proof.QueryRoundProofs[0].InitialTreeProof.EvalsProofs[0].X) == int(s1))

// // // NUM_EVALS_2
// // s2 := common_data.Config.NumWires
// // println(len(opening_proof.QueryRoundProofs[0].InitialTreeProof.EvalsProofs[1].X) == int(s2))

// // // NUM_EVALS_3
// // s3 := common_data.Config.NumChallenges * (1 + common_data.NumPartialProducts + common_data.NumLookupPolys)
// // println(len(opening_proof.QueryRoundProofs[0].InitialTreeProof.EvalsProofs[2].X) == int(s3))

// // // NUM_EVALS_4
// // s4 := common_data.Config.NumChallenges * common_data.QuotientDegreeFactor
// // println(len(opening_proof.QueryRoundProofs[0].InitialTreeProof.EvalsProofs[3].X) == int(s4))

// // INITIAL_EVAL_PROOF_SIBLINGS
// println(len(opening_proof.QueryRoundProofs[0].InitialTreeProof.EvalsProofs[0].Y.Siblings) == int(common_data.FriParams.DegreeBits+common_data.Config.FriConfig.RateBits-common_data.FriParams.Config.CapHeight))
// // NUM_STEPS
// println(len(opening_proof.QueryRoundProofs[0].Steps) == len(common_data.FriParams.ReductionArityBits))
// // LEVEL_EVALS = [total evals (0..NUM_STEPS)]
// println(len(opening_proof.QueryRoundProofs[0].Steps[0].Evals) == (1 << common_data.FriParams.ReductionArityBits[0]))
// // LEVEL_SIBLINGS
// // total_len_tree := common_data.FriParams.DegreeBits + common_data.Config.FriConfig.RateBits - common_data.FriParams.Config.CapHeight
// siblings := total_len_tree - common_data.FriParams.ReductionArityBits[0]
// println(int(siblings) == len(opening_proof.QueryRoundProofs[0].Steps[0].MerkleProof.Siblings))
// sum := uint64(0)
// for _, num := range common_data.FriParams.ReductionArityBits {
// 	sum += num
// }
// // FINAL_POLY_COEFFS
// println(len(opening_proof.FinalPoly.Coeffs) == (1 << int(common_data.FriParams.DegreeBits-sum)))
