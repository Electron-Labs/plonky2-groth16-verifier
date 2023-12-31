package verifier

import (
	"math/bits"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/Electron-Labs/plonky2-groth16-verifier/poseidon"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/fri"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/hash"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/plonk"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/plonk/gates"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/types"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

const NUM_COINS_LOOKUP = 4

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
	api        frontend.API
	commonData types.CommonData
}

func createVerifier(api frontend.API, commonData types.CommonData) *Verifier {
	return &Verifier{
		api:        api,
		commonData: commonData,
	}
}

// returns a%b in a constrained way
func modulus(api frontend.API, rangeChecker frontend.Rangechecker, a frontend.Variable, b frontend.Variable, n int) frontend.Variable {
	result, err := api.Compiler().NewHint(goldilocks.ModulusHint, 2, a, b)
	if err != nil {
		panic(err)
	}
	api.AssertIsEqual(api.Add(api.Mul(result[0], b), result[1]), a)
	rangeChecker.Check(result[0], 64-n) // 64 because we are calling modulus with `a` < goldilocks MODULUS
	rangeChecker.Check(result[1], n)
	goldilocks.LessThan(api, rangeChecker, result[1], b, n)

	return result[1]
}

// Range check everything is in goldilocks field
func fieldCheckInputs(api frontend.API, rangeChecker frontend.Rangechecker, proof types.ProofVariable, verifier_only types.VerifierOnlyVariable, pub_inputs types.PublicInputsVariable) error {
	// 1. Inputs should all be within goldilocks field
	for _, x := range pub_inputs {
		goldilocks.RangeCheck(api, rangeChecker, x.Limb)
	}

	// 2. All proof elements should be within goldilocks field
	for _, x := range proof.WiresCap {
		x.ApplyRangeCheck(goldilocks.RangeCheck, api, rangeChecker)
	}
	for _, x := range proof.PlonkZsPartialProductsCap {
		x.ApplyRangeCheck(goldilocks.RangeCheck, api, rangeChecker)
	}
	for _, x := range proof.QuotientPolysCap {
		x.ApplyRangeCheck(goldilocks.RangeCheck, api, rangeChecker)
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
			m.ApplyRangeCheck(goldilocks.RangeCheck, api, rangeChecker)
		}
	}

	for _, q := range proof.OpeningProof.QueryRoundProofs {
		// initial tree proof
		for _, e := range q.InitialTreeProof.EvalsProofs {
			for _, x := range e.X {
				goldilocks.RangeCheck(api, rangeChecker, x.Limb)
			}
			for _, m := range e.Y.Siblings {
				m.ApplyRangeCheck(goldilocks.RangeCheck, api, rangeChecker)
			}
		}

		// steps
		for _, s := range q.Steps {
			// evals
			for _, e := range s.Evals {
				e.RangeCheck(api, rangeChecker)
			}
			for _, m := range s.MerkleProof.Siblings {
				m.ApplyRangeCheck(goldilocks.RangeCheck, api, rangeChecker)
			}
		}
	}

	for _, o := range proof.OpeningProof.FinalPoly.Coeffs {
		o.RangeCheck(api, rangeChecker)
	}

	goldilocks.RangeCheck(api, rangeChecker, proof.OpeningProof.PowWitness.Limb)

	// 3. All verifier data elements should be in field too
	for _, x := range verifier_only.ConstantSigmasCap {
		x.ApplyRangeCheck(goldilocks.RangeCheck, api, rangeChecker)
	}
	verifier_only.CircuitDigest.ApplyRangeCheck(goldilocks.RangeCheck, api, rangeChecker)

	return nil
}

func hashPublicInputs(api frontend.API, rangeChecker frontend.Rangechecker, publicInputs types.PublicInputsVariable) types.HashOutVariable {
	poseidon_goldilocks := &poseidon.PoseidonGoldilocks{}
	hasher := hash.NewHasher(api, rangeChecker, poseidon_goldilocks)
	return hasher.HashNoPad(publicInputs)
}

func friChallenges(api frontend.API, rangeChecker frontend.Rangechecker, challenger *Challenger, openingProof types.FriProofVariable) types.FriChallengesVariable {
	numQueries := len(openingProof.QueryRoundProofs)
	ldeSize := (1 << len(openingProof.QueryRoundProofs[0].InitialTreeProof.EvalsProofs[0].Y.Siblings)) * len(openingProof.CommitPhaseMerkleCap[0])
	ldeBits := bits.Len(uint(ldeSize))

	var friChallenges types.FriChallengesVariable

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
		friChallenges.FriQueryIndices[i] = modulus(api, rangeChecker, tmpChallenge.Limb, ldeSize, ldeBits)
	}

	return friChallenges
}

func getChallenges(api frontend.API, rangeChecker frontend.Rangechecker, proof types.ProofVariable, publicInputHash types.HashOutVariable, circuitDigest types.HashOutVariable) types.ProofChallengesVariable {
	var challenges types.ProofChallengesVariable
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

	challenger.ObserveOpenings(fri.GetFriOpenings(proof.Openings))

	friChallenges := friChallenges(api, rangeChecker, &challenger, proof.OpeningProof)
	challenges.FriChallenges = friChallenges
	return challenges
}

func verifyWithChallenges(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	proof types.ProofVariable,
	public_inputs_hash types.HashOutVariable,
	challenges types.ProofChallengesVariable,
	verifier_data types.VerifierOnlyVariable,
	common_data types.CommonData,
) {
	local_constants := proof.Openings.Constants
	local_wires := proof.Openings.Wires
	vars := gates.EvaluationVars{
		LocalConstants:   local_constants,
		LocalWires:       local_wires,
		PublicInputsHash: public_inputs_hash,
	}
	local_zs := proof.Openings.PlonkZs
	next_zs := proof.Openings.PlonkZsNext
	local_lookup_zs := proof.Openings.LookupZs
	next_lookup_zs := proof.Openings.LookupZsNext
	s_sigmas := proof.Openings.PlonkSigmas
	partial_products := proof.Openings.PartialProducts

	zeta := challenges.PlonkZeta
	zeta_pow_deg := goldilocks.ExpPow2Ext(api, rangeChecker, zeta, int(common_data.FriParams.DegreeBits))
	z_h_zeta := zeta_pow_deg
	z_h_zeta.A.Limb = api.Sub(z_h_zeta.A.Limb, 1)

	vanishing_polys_zeta := plonk.EvalVanishingPoly(
		api,
		rangeChecker,
		common_data,
		zeta,
		zeta_pow_deg,
		vars,
		local_zs,
		next_zs,
		local_lookup_zs,
		next_lookup_zs,
		partial_products,
		s_sigmas,
		challenges.PlonkBetas,
		challenges.PlonkGammas,
		challenges.PlonkAlphas,
		challenges.PlonkDeltas,
	)

	quotient_polys_zeta := proof.Openings.QuotientPolys

	chunk_size := int(common_data.QuotientDegreeFactor)
	num_chunks := (len(quotient_polys_zeta)-1)/chunk_size + 1
	for i := 0; i < num_chunks; i++ {
		chunk := quotient_polys_zeta[i*chunk_size : min((i+1)*chunk_size, len(quotient_polys_zeta))]
		r_w_p := plonk.ReduceWithPowers(api, rangeChecker, chunk, zeta_pow_deg)
		rhs := goldilocks.MulExt(api, rangeChecker, z_h_zeta, r_w_p)
		lhs := vanishing_polys_zeta[i]
		api.AssertIsEqual(lhs.A.Limb, rhs.A.Limb)
		api.AssertIsEqual(lhs.B.Limb, rhs.B.Limb)
	}

	merkle_caps := []types.MerkleCapVariable{
		verifier_data.ConstantSigmasCap,
		proof.WiresCap,
		proof.PlonkZsPartialProductsCap,
		proof.QuotientPolysCap,
	}

	fri.VerifyFriProof(
		api,
		rangeChecker,
		fri.GetFriInstance(api, rangeChecker, common_data, zeta),
		fri.GetFriOpenings(proof.Openings),
		challenges.FriChallenges,
		merkle_caps,
		proof.OpeningProof,
		common_data.FriParams,
	)
}

func (circuit *Verifier) Verify(proof types.ProofVariable, verifier_only types.VerifierOnlyVariable, pub_inputs types.PublicInputsVariable) error {
	rangeChecker := rangecheck.New(circuit.api)
	fieldCheckInputs(circuit.api, rangeChecker, proof, verifier_only, pub_inputs)
	pubInputsHash := hashPublicInputs(circuit.api, rangeChecker, pub_inputs)
	circuit.api.Println(pubInputsHash)
	challenges := getChallenges(circuit.api, rangeChecker, proof, pubInputsHash, verifier_only.CircuitDigest)
	circuit.api.Println(challenges)
	verifyWithChallenges(circuit.api, rangeChecker, proof, pubInputsHash, challenges, verifier_only, circuit.commonData)
	return nil
}
