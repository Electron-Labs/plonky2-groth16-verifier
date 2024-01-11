package types

import (
	"encoding/json"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
)

type HashOut struct {
	HashOut []uint64 `json:"elements"`
}

func (hashout *HashOut) GetVariable() PoseidonGoldilocksHashOut {
	var hashOutVariable PoseidonGoldilocksHashOut
	hashOutVariable.HashOut = goldilocks.GetGoldilocksVariableArr(hashout.HashOut)

	return hashOutVariable
}

type MerkleCap []HashOut

func (merkle_cap *MerkleCap) GetVariable() MerkleCapVariable {
	var merkleCapVariable MerkleCapVariable
	for _, elm := range *merkle_cap {
		e := elm.GetVariable()
		merkleCapVariable = append(merkleCapVariable, e)
	}

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
	QueryRoundProofs     []FriQueryRound  `json:"query_round_proofs"`
	FinalPoly            PolynomialCoeffs `json:"final_poly"`
	PowWitness           uint64           `json:"pow_witness"`
}

func (fri_proof *FriProof) GetVariable() FriProofVariable {
	var friProofVariable FriProofVariable
	for _, elm := range fri_proof.CommitPhaseMerkleCap {
		e := elm.GetVariable()
		friProofVariable.CommitPhaseMerkleCap = append(friProofVariable.CommitPhaseMerkleCap, e)
	}
	for _, elm := range fri_proof.QueryRoundProofs {
		e := elm.GetVariable()
		friProofVariable.QueryRoundProofs = append(friProofVariable.QueryRoundProofs, e)
	}
	friProofVariable.FinalPoly = fri_proof.FinalPoly.GetVariable()
	friProofVariable.PowWitness = goldilocks.GetGoldilocksVariable(fri_proof.PowWitness)

	return friProofVariable
}

type Proof struct {
	WiresCap                  MerkleCap  `json:"wires_cap"`
	PlonkZsPartialProductsCap MerkleCap  `json:"plonk_zs_partial_products_cap"`
	QuotientPolysCap          MerkleCap  `json:"quotient_polys_cap"`
	Openings                  OpeningSet `json:"openings"`
	OpeningProof              FriProof   `json:"opening_proof"`
}

func (proof *Proof) GetVariable() ProofVariable {
	var proofVariable ProofVariable
	proofVariable.WiresCap = proof.WiresCap.GetVariable()
	proofVariable.PlonkZsPartialProductsCap = proof.PlonkZsPartialProductsCap.GetVariable()
	proofVariable.QuotientPolysCap = proof.QuotientPolysCap.GetVariable()
	proofVariable.Openings = proof.Openings.GetVariable()
	proofVariable.OpeningProof = proof.OpeningProof.GetVariable()

	return proofVariable
}

type VerifierOnly struct {
	ConstantSigmasCap MerkleCap `json:"constants_sigmas_cap"`
	CircuitDigest     HashOut   `json:"circuit_digest"`
}

type PublicInputs []uint64

func (public_inputs PublicInputs) GetVariable() PublicInputsVariable {
	var public_inputs_variables PublicInputsVariable
	for _, elm := range public_inputs {
		e := goldilocks.GetGoldilocksVariable(elm)
		public_inputs_variables = append(public_inputs_variables, e)
	}
	return public_inputs_variables
}

func (verifier_only *VerifierOnly) GetVariable() VerifierOnlyVariable {
	var verifierOnlyVariable VerifierOnlyVariable
	verifierOnlyVariable.ConstantSigmasCap = verifier_only.ConstantSigmasCap.GetVariable()
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

type FriReductionStrategy struct {
	// TODO: supports only constant Arity Bits right now, expand further
	ConstantArityBits []uint64 `json:"ConstantArityBits"`
}

type FriConfig struct {
	RateBits          uint64               `json:"rate_bits"`
	CapHeight         uint64               `json:"cap_height"`
	ProofOfWorkBits   uint32               `json:"proof_of_work_bits"`
	ReductionStrategy FriReductionStrategy `json:"reduction_strategy"` // [TODO remove later if goes unused]
	NumQueryRounds    uint64               `json:"num_query_rounds"`
}

type FriParams struct {
	Config             FriConfig `json:"config"`
	Hiding             bool      `json:"hiding"`
	DegreeBits         uint64    `json:"degree_bits"`
	ReductionArityBits []uint64  `json:"reduction_arity_bits"`
}

type CircuitConfig struct {
	NumWires                uint64    `json:"num_wires"`
	NumRoutedWires          uint64    `json:"num_routed_wires"`
	NumConstants            uint64    `json:"num_constants"`
	UseBaseArithmeticGate   bool      `json:"use_base_arithmetic_gate"`
	SecurityBits            uint64    `json:"security_bits"`
	NumChallenges           uint64    `json:"num_challenges"`
	ZeroKnowledge           bool      `json:"zero_knowledge"`
	MaxQuotientDegreeFactor uint64    `json:"max_quotient_degree_factor"`
	FriConfig               FriConfig `json:"fri_config"`
}

type GateRef struct {
	Gate string
}

type Range struct {
	Start uint64 `json:"start"`
	End   uint64 `json:"end"`
}

type SelectorsInfo struct {
	SelectorIndices []uint64 `json:"selector_indices"`
	Groups          []Range  `json:"groups"`
}

func (s *SelectorsInfo) NumSelectors() int {
	return len(s.Groups)
}

type LookupTable struct {
	a uint16
	b uint16
}

type CommonData struct {
	Config               CircuitConfig `json:"config"`
	FriParams            FriParams     `json:"fri_params"`
	Gates                []string      `json:"gates"`
	SelectorsInfo        SelectorsInfo `json:"selectors_info"`
	QuotientDegreeFactor uint64        `json:"quotient_degree_factor"`
	NumGateConstraints   uint64        `json:"num_gate_constraints"`
	NumConstants         uint64        `json:"num_constants"`
	NumPublicInputs      uint64        `json:"num_public_inputs"`
	KIs                  []uint64      `json:"k_is"`
	NumPartialProducts   uint64        `json:"num_partial_products"`
	NumLookupPolys       uint64        `json:"num_lookup_polys"`
	NumLookupSelectors   uint64        `json:"num_lookup_selectors"`
	Luts                 []LookupTable `json:"luts"`
}
