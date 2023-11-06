package verifier

import (
	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark/frontend"
)

const HASH_OUT = 4

type HashOutVariable struct {
	HashOut []goldilocks.GoldilocksVariable
}

func (hashOut *HashOutVariable) applyRangeCheck(rangeCheck func(frontend.API, frontend.Rangechecker, frontend.Variable), api frontend.API, rangeChecker frontend.Rangechecker) {
	for _, h := range hashOut.HashOut {
		rangeCheck(api, rangeChecker, h.Limb)
	}
}

func (hashOut *HashOutVariable) make() {
	hashOut.HashOut = make([]goldilocks.GoldilocksVariable, HASH_OUT)
}

type MerkleCapVariable []HashOutVariable

type MerkleProofVariable struct {
	Siblings []HashOutVariable
}

type EvalProofVariable struct {
	X []goldilocks.GoldilocksVariable
	Y MerkleProofVariable
}
type FriInitialTreeProofVariable struct {
	EvalsProofs []EvalProofVariable
}

type FriQueryStepVariable struct {
	Evals       []goldilocks.GoldilocksExtension2Variable
	MerkleProof MerkleProofVariable
}

type FriQueryRoundVariable struct {
	InitialTreeProof FriInitialTreeProofVariable
	Steps            []FriQueryStepVariable
}

type OpeningSetVariable struct {
	Constants       []goldilocks.GoldilocksExtension2Variable
	PlonkSigmas     []goldilocks.GoldilocksExtension2Variable
	Wires           []goldilocks.GoldilocksExtension2Variable
	PlonkZs         []goldilocks.GoldilocksExtension2Variable
	PlonkZsNext     []goldilocks.GoldilocksExtension2Variable
	PartialProducts []goldilocks.GoldilocksExtension2Variable
	QuotientPolys   []goldilocks.GoldilocksExtension2Variable
	LookupZs        []goldilocks.GoldilocksExtension2Variable
	LookupZsNext    []goldilocks.GoldilocksExtension2Variable
}

type PolynomialCoeffsVariable struct {
	Coeffs []goldilocks.GoldilocksExtension2Variable
}

type FriProofVariable struct {
	CommitPhaseMerkleCap []MerkleCapVariable
	QueryRoundProofs     []FriQueryRoundVariable
	FinalPoly            PolynomialCoeffsVariable
	PowWitness           goldilocks.GoldilocksVariable
}

type ProofVariable struct {
	WiresCap                  MerkleCapVariable
	PlonkZsPartialProductsCap MerkleCapVariable
	QuotientPolysCap          MerkleCapVariable
	Openings                  OpeningSetVariable
	OpeningProof              FriProofVariable
}

type VerifierOnlyVariable struct {
	ConstantSigmasCap MerkleCapVariable
	CircuitDigest     HashOutVariable
}

type PublicInputsVariable []goldilocks.GoldilocksVariable

type FriChallengesVariable struct {
	FriAlpha        goldilocks.GoldilocksExtension2Variable
	FriBetas        []goldilocks.GoldilocksExtension2Variable
	FriPowResponse  goldilocks.GoldilocksVariable
	FriQueryIndices []frontend.Variable
}

type ProofChallengesVariable struct {
	PlonkBetas    []goldilocks.GoldilocksVariable
	PlonkGammas   []goldilocks.GoldilocksVariable
	PlonkAlphas   []goldilocks.GoldilocksVariable
	PlonkDeltas   []goldilocks.GoldilocksVariable
	PlonkZeta     goldilocks.GoldilocksExtension2Variable
	FriChallenges FriChallengesVariable
}
