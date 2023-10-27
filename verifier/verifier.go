package verifier

import (
	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

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

type Verifier struct {
	api         frontend.API
	common_data CommonData
}

func createVerifier(api frontend.API, common_data CommonData) *Verifier {
	return &Verifier{
		api:         api,
		common_data: common_data,
	}
}

func (circuit *Verifier) Verify(proof ProofVariable, verifier_only VerifierOnlyVariable, pub_inputs PublicInputsVariable) error {
	rangeChecker := rangecheck.New(circuit.api)
	goldilocks.Reduce(circuit.api, rangeChecker, proof.OpeningProof.PowWitness.Limb)
	return nil
}
