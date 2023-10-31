package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetCircuitConstants(t *testing.T) {

	commonDataPath := "../data/goldilocks/common_data.json"
	proofPath := "../data/goldilocks/proof_with_pis.json"
	proof, err := read_proof_from_file(proofPath)
	if err != nil {
		t.Fatal("Error in reading proof file: ", commonDataPath)
	}
	circuitConstans := getCircuitConstants(commonDataPath)

	assert.Equal(t, len(proof.WiresCap), int(circuitConstans.CAP_LEN))
	assert.Equal(t, len(proof.PlonkZsPartialProductsCap), int(circuitConstans.CAP_LEN))
	assert.Equal(t, len(proof.QuotientPolysCap), int(circuitConstans.CAP_LEN))

	opening_set := proof.Openings
	assert.Equal(t, len(opening_set.Constants), int(circuitConstans.CONSTANTS))
	assert.Equal(t, len(opening_set.PlonkSigmas), int(circuitConstans.PLONK_SIGMAS))
	assert.Equal(t, len(opening_set.Wires), int(circuitConstans.WIRES))
	assert.Equal(t, len(opening_set.PlonkZs), int(circuitConstans.PLONK_ZS))
	assert.Equal(t, len(opening_set.PlonkZsNext), int(circuitConstans.PLONK_ZS))
	assert.Equal(t, len(opening_set.PartialProducts), int(circuitConstans.PARTIAL_PRODUCTS))
	assert.Equal(t, len(opening_set.QuotientPolys), int(circuitConstans.QUOTIENT_POLYS))
	assert.Equal(t, len(opening_set.LookupZs), int(circuitConstans.LOOKUP_ZS))
	assert.Equal(t, len(opening_set.LookupZsNext), int(circuitConstans.LOOKUP_ZS))

	opening_proof := proof.OpeningProof
	assert.Equal(t, len(opening_proof.CommitPhaseMerkleCap), len(circuitConstans.LEVEL_EVALS))
	for _, cap := range opening_proof.CommitPhaseMerkleCap {
		assert.Equal(t, len(cap), int(circuitConstans.CAP_LEN))
	}
	assert.Equal(t, len(opening_proof.QueryRoundProofs), int(circuitConstans.NUM_QUERY_ROUNDS))
	num_evals := []uint64{circuitConstans.NUM_EVALS_1, circuitConstans.NUM_EVALS_2, circuitConstans.NUM_EVALS_3, circuitConstans.NUM_EVALS_4}
	for _, qrp := range opening_proof.QueryRoundProofs {
		assert.Equal(t, len(qrp.InitialTreeProof.EvalsProofs), int(circuitConstans.NUM_INITIAL_EVAL_PROOFS))
		for i, eval_proof := range qrp.InitialTreeProof.EvalsProofs {
			assert.Equal(t, len(eval_proof.X), int(num_evals[i]))
			assert.Equal(t, len(eval_proof.Y.Siblings), int(circuitConstans.INITIAL_EVAL_PROOF_SIBLINGS))
		}
		assert.Equal(t, len(qrp.Steps), len(circuitConstans.LEVEL_EVALS))
		for i, step := range qrp.Steps {
			assert.Equal(t, len(step.Evals), int(circuitConstans.LEVEL_EVALS[i]))
			assert.Equal(t, len(step.MerkleProof.Siblings), int(circuitConstans.LEVEL_SIBLINGS[i]))
		}
	}
	assert.Equal(t, len(opening_proof.FinalPoly.Coeffs), int(circuitConstans.FINAL_POLY_COEFFS))
}
