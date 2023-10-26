package verifier

import (
	"encoding/json"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
)

type HashOut struct {
	HashOut []uint64 `json:"elements"`
}

func (hashout *HashOut) GetVariable() HashOutVariable {
	var hashOutVariable HashOutVariable
	hashOutVariable.HashOut = goldilocks.GetGoldilocksVariableArr(hashout.HashOut)

	return hashOutVariable
}

type MerkleCap struct {
	Elements []uint64 `json:"elements"`
}

func (merkle_cap *MerkleCap) GetVariable() MerkleCapVariable {
	var merkleCapVariable MerkleCapVariable
	merkleCapVariable.Elements = goldilocks.GetGoldilocksVariableArr(merkle_cap.Elements)

	return merkleCapVariable
}

type MerkleProof struct {
	Siblings []HashOut `json:"siblings"`
}

func (merkle_proof *MerkleProof) GetVariable() MerkleProofVariable {
	var merkleProofVariable MerkleProofVariable
	for _, elm := range merkle_proof.Siblings {
		e := elm.GetVariable()
		merkleProofVariable.Siblings = append(merkleProofVariable.Siblings, e)
	}

	return merkleProofVariable
}

type EvalProof struct {
	X []uint64
	Y MerkleProof
}

func (eval_proof *EvalProof) GetVariable() EvalProofVariable {
	var evalProofVariable EvalProofVariable
	evalProofVariable.X = goldilocks.GetGoldilocksVariableArr(eval_proof.X)
	evalProofVariable.Y = eval_proof.Y.GetVariable()

	return evalProofVariable
}

type FriInitialTreeProof struct {
	EvalsProofs []EvalProof `json:"evals_proofs"`
}

func (fri_initial_tree_proof *FriInitialTreeProof) GetVariable() FriInitialTreeProofVariable {
	var friInitialTreeProofVariable FriInitialTreeProofVariable
	for _, elm := range fri_initial_tree_proof.EvalsProofs {
		e := elm.GetVariable()
		friInitialTreeProofVariable.EvalsProofs = append(friInitialTreeProofVariable.EvalsProofs, e)
	}

	return friInitialTreeProofVariable
}

type FriQueryStep struct {
	Evals       [][]uint64  `json:"evals"`
	MerkleProof MerkleProof `json:"merkle_proof"`
}

func (fri_query_step *FriQueryStep) GetVariable() FriQueryStepVariable {
	var friQueryStepVariable FriQueryStepVariable
	friQueryStepVariable.Evals = goldilocks.GetGoldilocksExtensionVariableArr(fri_query_step.Evals)
	friQueryStepVariable.MerkleProof = fri_query_step.MerkleProof.GetVariable()

	return friQueryStepVariable
}

type FriQueryRound struct {
	InitialTreeProof FriInitialTreeProof `json:"initial_trees_proof"`
	Steps            []FriQueryStep      `json:"steps"`
}

func (fri_query_round *FriQueryRound) GetVariable() FriQueryRoundVariable {
	var friQueryRoundVariable FriQueryRoundVariable
	friQueryRoundVariable.InitialTreeProof = fri_query_round.InitialTreeProof.GetVariable()
	for _, elm := range fri_query_round.Steps {
		e := elm.GetVariable()
		friQueryRoundVariable.Steps = append(friQueryRoundVariable.Steps, e)
	}

	return friQueryRoundVariable
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

func (opening_set *OpeningSet) GetVariable() OpeningSetVariable {
	var openingSetVariable OpeningSetVariable
	openingSetVariable.Constants = goldilocks.GetGoldilocksExtensionVariableArr(opening_set.Constants)
	openingSetVariable.PlonkSigmas = goldilocks.GetGoldilocksExtensionVariableArr(opening_set.PlonkSigmas)
	openingSetVariable.Wires = goldilocks.GetGoldilocksExtensionVariableArr(opening_set.Wires)
	openingSetVariable.PlonkZs = goldilocks.GetGoldilocksExtensionVariableArr(opening_set.PlonkZs)
	openingSetVariable.PlonkZsNext = goldilocks.GetGoldilocksExtensionVariableArr(opening_set.PlonkZsNext)
	openingSetVariable.PartialProducts = goldilocks.GetGoldilocksExtensionVariableArr(opening_set.PartialProducts)
	openingSetVariable.QuotientPolys = goldilocks.GetGoldilocksExtensionVariableArr(opening_set.QuotientPolys)
	openingSetVariable.LookupZs = goldilocks.GetGoldilocksExtensionVariableArr(opening_set.LookupZs)
	openingSetVariable.LookupZsNext = goldilocks.GetGoldilocksExtensionVariableArr(opening_set.LookupZsNext)

	return openingSetVariable
}

type PolynomialCoeffs struct {
	Coeffs [][]uint64 `json:"coeffs"`
}

func (poly_coeffs *PolynomialCoeffs) GetVariable() PolynomialCoeffsVariable {
	var polynomialCoeffsVariable PolynomialCoeffsVariable
	polynomialCoeffsVariable.Coeffs = goldilocks.GetGoldilocksExtensionVariableArr(poly_coeffs.Coeffs)

	return polynomialCoeffsVariable
}

type FriProof struct {
	CommitPhaseMerkleCap []MerkleCap      `json:"commit_phase_merkle_caps"`
	QueryRroundProofs    []FriQueryRound  `json:"query_round_proofs"`
	FinalPoly            PolynomialCoeffs `json:"final_poly"`
	PowWitness           uint64           `json:"pow_witness"`
}

func (fri_proof *FriProof) GetVariable() FriProofVariable {
	var friProofVariable FriProofVariable
	for _, elm := range fri_proof.CommitPhaseMerkleCap {
		e := elm.GetVariable()
		friProofVariable.CommitPhaseMerkleCap = append(friProofVariable.CommitPhaseMerkleCap, e)
	}
	for _, elm := range fri_proof.QueryRroundProofs {
		e := elm.GetVariable()
		friProofVariable.QueryRroundProofs = append(friProofVariable.QueryRroundProofs, e)
	}
	friProofVariable.FinalPoly = fri_proof.FinalPoly.GetVariable()
	friProofVariable.PowWitness = goldilocks.GetGoldilocksVariable(fri_proof.PowWitness)

	return friProofVariable
}

type Proof struct {
	WiresCap                  []MerkleCap `json:"wires_cap"`
	PlonkZsPartialProductsCap []MerkleCap `json:"plonk_zs_partial_products_cap"`
	QuotientPolysCap          []MerkleCap `json:"quotient_polys_cap"`
	Openings                  OpeningSet  `json:"openings"`
	OpeningProof              FriProof    `json:"opening_proof"`
}

func (proof *Proof) GetVariable() ProofVariable {
	var proofVariable ProofVariable
	for _, elm := range proof.WiresCap {
		e := elm.GetVariable()
		proofVariable.WiresCap = append(proofVariable.WiresCap, e)
	}
	for _, elm := range proof.PlonkZsPartialProductsCap {
		e := elm.GetVariable()
		proofVariable.PlonkZsPartialProductsCap = append(proofVariable.PlonkZsPartialProductsCap, e)
	}
	for _, elm := range proof.QuotientPolysCap {
		e := elm.GetVariable()
		proofVariable.QuotientPolysCap = append(proofVariable.QuotientPolysCap, e)
	}
	proofVariable.Openings = proof.Openings.GetVariable()
	proofVariable.OpeningProof = proof.OpeningProof.GetVariable()

	return proofVariable
}

type VerifierOnly struct {
	ConstantSigmasCap []MerkleCap `json:"constants_sigmas_cap"`
	CircuitDigest     HashOut     `json:"circuit_digest"`
}

func (verifier_only *VerifierOnly) GetVariable() VerifierOnlyVariable {
	var verifierOnlyVariable VerifierOnlyVariable
	for _, elm := range verifier_only.ConstantSigmasCap {
		e := elm.GetVariable()
		verifierOnlyVariable.ConstantSigmasCap = append(verifierOnlyVariable.ConstantSigmasCap, e)
	}
	verifierOnlyVariable.CircuitDigest = verifier_only.CircuitDigest.GetVariable()

	return verifierOnlyVariable
}

func (n *EvalProof) UnmarshalJSON(buf []byte) error {
	tmp := []interface{}{&n.X, &n.Y}
	if err := json.Unmarshal(buf, &tmp); err != nil {
		return err
	}
	return nil
}
