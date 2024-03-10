package verifier

import (
	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/types"
	"github.com/consensys/gnark/frontend"
)

type Runner struct {
	Proof            types.ProofVariable
	VerifierOnly     types.VerifierOnlyVariable
	Plonky2PubInputs types.Plonky2PublicInputsVariable
	GnarkPubInputs   types.GnarkPublicInputsVariable `gnark:",public"`
	CommonData       types.CommonData
}

func (circuit *Runner) Define(api frontend.API) error {
	// verifier := verifier.createVerifier(api, circuit.common_data)
	verifier := createVerifier(api, circuit.CommonData)
	verifier.Verify(circuit.Proof, circuit.VerifierOnly, circuit.Plonky2PubInputs, circuit.GnarkPubInputs)
	return nil
}

// TODO: very ugly function; structure it better
// TODO: requires intensive testing with various config/proofs combinations
func (circuit *Runner) Make(constants CircuitConstants, commonData types.CommonData) {
	circuit.CommonData = commonData
	circuit.Proof.WiresCap = make(types.MerkleCapVariable, constants.CAP_LEN)
	circuit.Proof.PlonkZsPartialProductsCap = make(types.MerkleCapVariable, constants.CAP_LEN)
	circuit.Proof.QuotientPolysCap = make(types.MerkleCapVariable, constants.CAP_LEN)

	circuit.Proof.Openings.Constants = make([]goldilocks.GoldilocksExtension2Variable, constants.CONSTANTS)
	circuit.Proof.Openings.PlonkSigmas = make([]goldilocks.GoldilocksExtension2Variable, constants.PLONK_SIGMAS)
	circuit.Proof.Openings.Wires = make([]goldilocks.GoldilocksExtension2Variable, constants.WIRES)
	circuit.Proof.Openings.PlonkZs = make([]goldilocks.GoldilocksExtension2Variable, constants.PLONK_ZS)
	circuit.Proof.Openings.PlonkZsNext = make([]goldilocks.GoldilocksExtension2Variable, constants.PLONK_ZS)
	circuit.Proof.Openings.PartialProducts = make([]goldilocks.GoldilocksExtension2Variable, constants.PARTIAL_PRODUCTS)
	circuit.Proof.Openings.QuotientPolys = make([]goldilocks.GoldilocksExtension2Variable, constants.QUOTIENT_POLYS)
	circuit.Proof.Openings.LookupZs = make([]goldilocks.GoldilocksExtension2Variable, constants.LOOKUP_ZS)
	circuit.Proof.Openings.LookupZsNext = make([]goldilocks.GoldilocksExtension2Variable, constants.LOOKUP_ZS)

	circuit.Proof.OpeningProof.CommitPhaseMerkleCap = make([]types.MerkleCapVariable, constants.COMMIT_PHASE_MERKLE_CAPS)
	for i := range circuit.Proof.OpeningProof.CommitPhaseMerkleCap {
		circuit.Proof.OpeningProof.CommitPhaseMerkleCap[i] = make(types.MerkleCapVariable, constants.CAP_LEN)
	}

	circuit.Proof.OpeningProof.QueryRoundProofs = make([]types.FriQueryRoundVariable, constants.NUM_QUERY_ROUNDS)
	num_evals := []uint64{constants.NUM_EVALS_1, constants.NUM_EVALS_2, constants.NUM_EVALS_3, constants.NUM_EVALS_4}
	for i := range circuit.Proof.OpeningProof.QueryRoundProofs {
		circuit.Proof.OpeningProof.QueryRoundProofs[i].InitialTreeProof.EvalsProofs = make([]types.EvalProofVariable, constants.NUM_INITIAL_EVAL_PROOFS)
		for j := range circuit.Proof.OpeningProof.QueryRoundProofs[i].InitialTreeProof.EvalsProofs {
			circuit.Proof.OpeningProof.QueryRoundProofs[i].InitialTreeProof.EvalsProofs[j].X = make([]goldilocks.GoldilocksVariable, num_evals[j])
			circuit.Proof.OpeningProof.QueryRoundProofs[i].InitialTreeProof.EvalsProofs[j].Y.Siblings = make([]types.PoseidonBn254HashOut, constants.INITIAL_EVAL_PROOF_SIBLINGS)
		}

		circuit.Proof.OpeningProof.QueryRoundProofs[i].Steps = make([]types.FriQueryStepVariable, constants.NUM_STEPS)
		for j := range circuit.Proof.OpeningProof.QueryRoundProofs[i].Steps {
			circuit.Proof.OpeningProof.QueryRoundProofs[i].Steps[j].Evals = make([]goldilocks.GoldilocksExtension2Variable, constants.LEVEL_EVALS[j])
			circuit.Proof.OpeningProof.QueryRoundProofs[i].Steps[j].MerkleProof.Siblings = make([]types.PoseidonBn254HashOut, constants.LEVEL_SIBLINGS[j])
		}
	}

	circuit.Proof.OpeningProof.FinalPoly.Coeffs = make([]goldilocks.GoldilocksExtension2Variable, constants.FINAL_POLY_COEFFS)

	circuit.VerifierOnly.ConstantSigmasCap = make(types.MerkleCapVariable, constants.CAP_LEN)
	circuit.Plonky2PubInputs = make(types.Plonky2PublicInputsVariable, constants.NUM_PLONKY2_PUBLIC_INPUTS)
	circuit.GnarkPubInputs = make(types.GnarkPublicInputsVariable, constants.NUM_GNARK_PUBLIC_INPUTS)
}
