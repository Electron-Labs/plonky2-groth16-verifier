package verifier

import (
	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

const NUM_COINS_LOOKUP = 4

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

type CircuitConstants struct {
	CAP_LEN                     uint64
	CONSTANTS                   uint64
	PLONK_SIGMAS                uint64
	WIRES                       uint64
	PLONK_ZS                    uint64
	PARTIAL_PRODUCTS            uint64
	QUOTIENT_POLYS              uint64
	LOOKUP_ZS                   uint64
	COMMIT_PHASE_MERKLE_CAPS    uint64
	NUM_QUERY_ROUNDS            uint64
	NUM_INITIAL_EVAL_PROOFS     uint64 // const : 4
	NUM_EVALS_1                 uint64
	NUM_EVALS_2                 uint64
	NUM_EVALS_3                 uint64
	NUM_EVALS_4                 uint64
	INITIAL_EVAL_PROOF_SIBLINGS uint64
	NUM_STEPS                   uint64
	LEVEL_EVALS                 []uint64
	LEVEL_SIBLINGS              []uint64 //= [siblings_len_for_each_level (0..NUM_STEPS)]
	FINAL_POLY_COEFFS           uint64
	NUM_PUBLIC_INPUTS           uint64
}

type Verifier struct {
	api frontend.API
}

func createVerifier(api frontend.API) *Verifier {
	return &Verifier{
		api: api,
	}
}

// returns a%b in a constrained way
func modulus(api frontend.API, rangeChecker frontend.Rangechecker, a frontend.Variable, b frontend.Variable) frontend.Variable {
	result, err := api.Compiler().NewHint(goldilocks.ModulusHint, 2, a, b)
	if err != nil {
		panic(err)
	}
	api.AssertIsEqual(api.Add(api.Mul(result[0], b), result[1]), a)

	goldilocks.LessThan(api, rangeChecker, result[1], b, 64)

	return result[1]
}

// Range check everything is in goldilocks field
func fieldCheckInputs(api frontend.API, rangeChecker frontend.Rangechecker, proof ProofVariable, verifier_only VerifierOnlyVariable, pub_inputs PublicInputsVariable) error {
	// 1. Inputs should all be within goldilocks field
	for _, x := range pub_inputs {
		goldilocks.RangeCheck(api, rangeChecker, x.Limb)
	}

	// 2. All proof elements should be within goldilocks field
	for _, x := range proof.WiresCap {
		x.applyRangeCheck(goldilocks.RangeCheck, api, rangeChecker)
	}
	for _, x := range proof.PlonkZsPartialProductsCap {
		x.applyRangeCheck(goldilocks.RangeCheck, api, rangeChecker)
	}
	for _, x := range proof.QuotientPolysCap {
		x.applyRangeCheck(goldilocks.RangeCheck, api, rangeChecker)
	}

	for _, x := range proof.Openings.Constants {
		x.RangeCheck(api, rangeChecker)
	}
	for _, x := range proof.Openings.PlonkSigmas {
		x.RangeCheck(api, rangeChecker)
	}
	for _, x := range proof.Openings.Wires {
		x.RangeCheck(api, rangeChecker)
	}
	for _, x := range proof.Openings.PlonkZs {
		x.RangeCheck(api, rangeChecker)
	}
	for _, x := range proof.Openings.PlonkZsNext {
		x.RangeCheck(api, rangeChecker)
	}
	for _, x := range proof.Openings.PartialProducts {
		x.RangeCheck(api, rangeChecker)
	}
	for _, x := range proof.Openings.QuotientPolys {
		x.RangeCheck(api, rangeChecker)
	}
	for _, x := range proof.Openings.LookupZs {
		x.RangeCheck(api, rangeChecker)
	}
	for _, x := range proof.Openings.LookupZsNext {
		x.RangeCheck(api, rangeChecker)
	}

	for _, x := range proof.OpeningProof.CommitPhaseMerkleCap {
		for _, m := range x {
			m.applyRangeCheck(goldilocks.RangeCheck, api, rangeChecker)
		}
	}

	for _, q := range proof.OpeningProof.QueryRoundProofs {
		// initial tree proof
		for _, e := range q.InitialTreeProof.EvalsProofs {
			for _, x := range e.X {
				goldilocks.RangeCheck(api, rangeChecker, x.Limb)
			}
			for _, m := range e.Y.Siblings {
				m.applyRangeCheck(goldilocks.RangeCheck, api, rangeChecker)
			}
		}

		// steps
		for _, s := range q.Steps {
			// evals
			for _, e := range s.Evals {
				e.RangeCheck(api, rangeChecker)
			}
			for _, m := range s.MerkleProof.Siblings {
				m.applyRangeCheck(goldilocks.RangeCheck, api, rangeChecker)
			}
		}
	}

	for _, o := range proof.OpeningProof.FinalPoly.Coeffs {
		o.RangeCheck(api, rangeChecker)
	}

	goldilocks.RangeCheck(api, rangeChecker, proof.OpeningProof.PowWitness.Limb)

	// 3. All verifier data elements should be in field too
	for _, x := range verifier_only.ConstantSigmasCap {
		x.applyRangeCheck(goldilocks.RangeCheck, api, rangeChecker)
	}
	verifier_only.CircuitDigest.applyRangeCheck(goldilocks.RangeCheck, api, rangeChecker)

	return nil
}

func hashPublicInputs(api frontend.API, rangeChecker frontend.Rangechecker, publicInputs PublicInputsVariable) HashOutVariable {
	hasher := NewHasher(api, rangeChecker)
	return hasher.HashNoPad(publicInputs)
}

func getFriOpenings(openings OpeningSetVariable) FriOpeningsVariable {
	var zeta_batch FriOpeningBatchVariable
	zeta_batch_len := len(openings.Constants) + len(openings.PlonkSigmas) + len(openings.Wires) + len(openings.PlonkZs) + len(openings.PartialProducts) + len(openings.QuotientPolys) + len(openings.LookupZs)
	zeta_batch.Values = make([]goldilocks.GoldilocksExtension2Variable, zeta_batch_len)
	i := 0
	for _, v := range openings.Constants {
		zeta_batch.Values[i] = v
		i += 1
	}
	for _, v := range openings.PlonkSigmas {
		zeta_batch.Values[i] = v
		i += 1
	}
	for _, v := range openings.Wires {
		zeta_batch.Values[i] = v
		i += 1
	}
	for _, v := range openings.PlonkZs {
		zeta_batch.Values[i] = v
		i += 1
	}
	for _, v := range openings.PartialProducts {
		zeta_batch.Values[i] = v
		i += 1
	}
	for _, v := range openings.QuotientPolys {
		zeta_batch.Values[i] = v
		i += 1
	}
	for _, v := range openings.LookupZs {
		zeta_batch.Values[i] = v
		i += 1
	}
	if i != zeta_batch_len {
		panic("Incorrect number of openings")
	}

	var zeta_next_batch FriOpeningBatchVariable
	zeta_next_batch_len := len(openings.PlonkZsNext) + len(openings.LookupZsNext)
	zeta_next_batch.Values = make([]goldilocks.GoldilocksExtension2Variable, zeta_next_batch_len)
	i = 0
	for _, v := range openings.PlonkZsNext {
		zeta_next_batch.Values[i] = v
		i += 1
	}
	for _, v := range openings.LookupZsNext {
		zeta_next_batch.Values[i] = v
		i += 1
	}
	if i != zeta_next_batch_len {
		panic("Incorrect number of openings")
	}

	var friOpenings FriOpeningsVariable
	friOpenings.Batches = make([]FriOpeningBatchVariable, 2)
	friOpenings.Batches[0] = zeta_batch
	friOpenings.Batches[1] = zeta_next_batch
	return friOpenings
}

func friChallenges(api frontend.API, rangeChecker frontend.Rangechecker, challenger *Challenger, openingProof FriProofVariable) FriChallengesVariable {
	numQueries := len(openingProof.QueryRoundProofs)
	ldeSize := (1 << len(openingProof.QueryRoundProofs[0].InitialTreeProof.EvalsProofs[0].Y.Siblings)) * len(openingProof.CommitPhaseMerkleCap[0])

	var friChallenges FriChallengesVariable

	friChallenges.FriAlpha = challenger.GetExtensionChallenge()
	friChallenges.FriBetas = make([]goldilocks.GoldilocksExtension2Variable, len(openingProof.CommitPhaseMerkleCap))
	for i, v := range openingProof.CommitPhaseMerkleCap {
		challenger.ObserveCap(v)
		friChallenges.FriBetas[i] = challenger.GetExtensionChallenge()
	}

	challenger.ObserveExtensionElements(openingProof.FinalPoly.Coeffs)

	challenger.ObserveElement(openingProof.PowWitness)

	friChallenges.FriPowResponse = challenger.GetChallenge()

	friChallenges.FriQueryIndices = make([]frontend.Variable, numQueries)
	for i := 0; i < numQueries; i++ {
		tmpChallenge := challenger.GetChallenge()
		friChallenges.FriQueryIndices[i] = modulus(api, rangeChecker, tmpChallenge.Limb, ldeSize)
	}

	return friChallenges
}

func getChallenges(api frontend.API, rangeChecker frontend.Rangechecker, proof ProofVariable, publicInputHash HashOutVariable, circuitDigest HashOutVariable) ProofChallengesVariable {
	var challenges ProofChallengesVariable
	challenger := NewChallenger(api, rangeChecker)
	hasLookup := len(proof.Openings.LookupZs) != 0

	challenger.ObserveHash(circuitDigest)
	challenger.ObserveHash(publicInputHash)

	challenger.ObserveCap(proof.WiresCap)

	numChallenges := len(proof.Openings.PlonkZs)

	challenges.PlonkBetas = challenger.GetNChallenges(numChallenges)
	challenges.PlonkGammas = challenger.GetNChallenges(numChallenges)

	if hasLookup {
		numLookupChallenges := NUM_COINS_LOOKUP * numChallenges
		numAdditionalChallenges := numLookupChallenges - 2*numChallenges
		additionalChallenges := challenger.GetNChallenges(numAdditionalChallenges)
		challenges.PlonkDeltas = make([]goldilocks.GoldilocksVariable, numLookupChallenges)
		for i, v := range challenges.PlonkBetas {
			challenges.PlonkDeltas[i] = v
		}
		for i, v := range challenges.PlonkGammas {
			challenges.PlonkDeltas[i+numChallenges] = v
		}
		for i, v := range additionalChallenges {
			challenges.PlonkDeltas[i+2*numChallenges] = v
		}
	} else {
		challenges.PlonkDeltas = make([]goldilocks.GoldilocksVariable, 0)
	}

	challenger.ObserveCap(proof.PlonkZsPartialProductsCap)
	challenges.PlonkAlphas = challenger.GetNChallenges(numChallenges)

	challenger.ObserveCap(proof.QuotientPolysCap)
	challenges.PlonkZeta = challenger.GetExtensionChallenge()

	challenger.ObserveOpenings(getFriOpenings(proof.Openings))

	friChallenges := friChallenges(api, rangeChecker, &challenger, proof.OpeningProof)
	challenges.FriChallenges = friChallenges
	return challenges
}

func (circuit *Verifier) Verify(proof ProofVariable, verifier_only VerifierOnlyVariable, pub_inputs PublicInputsVariable) error {
	rangeChecker := rangecheck.New(circuit.api)
	fieldCheckInputs(circuit.api, rangeChecker, proof, verifier_only, pub_inputs)
	pubInputsHash := hashPublicInputs(circuit.api, rangeChecker, pub_inputs)
	circuit.api.Println(pubInputsHash)
	challenges := getChallenges(circuit.api, rangeChecker, proof, pubInputsHash, verifier_only.CircuitDigest)
	circuit.api.Println(challenges)
	return nil
}
