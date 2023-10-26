package verifier

import (
	"encoding/json"
)

type HashOut struct {
	HashOut []uint64 `json:"elements"`
}

type MerkleCap struct {
	Elements []uint64 `json:"elements"`
}

type MerkleProof struct {
	Siblings []HashOut `json:"siblings"`
}

type EvalProof struct {
	X []uint64
	Y MerkleProof
}
type FriInitialTreeProof struct {
	EvalsProofs []EvalProof `json:"evals_proofs"`
}

type FriQueryStep struct {
	Evals       [][]uint64  `json:"evals"`
	MerkleProof MerkleProof `json:"merkle_proof"`
}

type FriQueryRound struct {
	InitialTreeProof FriInitialTreeProof `json:"initial_trees_proof"`
	Steps            []FriQueryStep      `json:"steps"`
}

type OpeningSet struct {
	Constants       [][]uint64 `json:"constants"`
	PlonkSigmas     [][]uint64 `json:"plonk_sigmas"`
	Wires           [][]uint64 `json:"wires"`
	PlonkZs         [][]uint64 `json:"plonk_zs"`
	PlonkZsNext     [][]uint64 `json:"plonk_zs_next"`
	PartialProducts [][]uint64 `json:"partial_products"`
	QuotientPolys   [][]uint64 `json:"quotient_polys"`
	LookupZs        [][]uint64 `json:"lookup_zs"`
	LookupZsNext    [][]uint64 `json:"lookup_zs_next"`
}

type PolynomialCoeffs struct {
	Coeffs [][]uint64 `json:"coeffs"`
}

type FriProof struct {
	CommitPhaseMerkleCap []MerkleCap      `json:"commit_phase_merkle_caps"`
	QueryRroundProofs    []FriQueryRound  `json:"query_round_proofs"`
	FinalPoly            PolynomialCoeffs `json:"final_poly"`
	PowWitness           uint64           `json:"pow_witness"`
}

type Proof struct {
	WiresCap                  []MerkleCap `json:"wires_cap"`
	PlonkZsPartialProductsCap []MerkleCap `json:"plonk_zs_partial_products_cap"`
	QuotientPolysCap          []MerkleCap `json:"quotient_polys_cap"`
	Openings                  OpeningSet  `json:"openings"`
	OpeningProof              FriProof    `json:"opening_proof"`
}

type VerifierOnly struct {
	ConstantSigmasCap []MerkleCap `json:"constants_sigmas_cap"`
	CircuitDigest     HashOut     `json:"circuit_digest"`
}

func (n *EvalProof) UnmarshalJSON(buf []byte) error {
	tmp := []interface{}{&n.X, &n.Y}
	if err := json.Unmarshal(buf, &tmp); err != nil {
		return err
	}
	return nil
}
