package types

import (
	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark/frontend"
)

const POSEIDON_Bn254_HASH_OUT = 1
const POSEIDON_GOLDILOCKS_HASH_OUT = 4
const SALT_SIZE = 4

type PoseidonGoldilocksHashOut struct {
	HashOut []goldilocks.GoldilocksVariable
}

type PoseidonBn254HashOut struct {
	HashOut frontend.Variable
}

func SelectHashOut(api frontend.API, b frontend.Variable, in1 PoseidonGoldilocksHashOut, in2 PoseidonGoldilocksHashOut) PoseidonGoldilocksHashOut {
	var out PoseidonGoldilocksHashOut
	out.HashOut = make([]goldilocks.GoldilocksVariable, POSEIDON_GOLDILOCKS_HASH_OUT)
	for i := 0; i < POSEIDON_GOLDILOCKS_HASH_OUT; i++ {
		out.HashOut[i].Limb = api.Select(b, in1.HashOut[i].Limb, in2.HashOut[i].Limb)
	}
	return out
}

func SelectHashoutLookup2(api frontend.API, b0 frontend.Variable, b1 frontend.Variable, in0 PoseidonGoldilocksHashOut, in1 PoseidonGoldilocksHashOut, in2 PoseidonGoldilocksHashOut, in3 PoseidonGoldilocksHashOut) PoseidonGoldilocksHashOut {
	var out PoseidonGoldilocksHashOut
	out.HashOut = make([]goldilocks.GoldilocksVariable, POSEIDON_GOLDILOCKS_HASH_OUT)
	for i := 0; i < POSEIDON_GOLDILOCKS_HASH_OUT; i++ {
		out.HashOut[i].Limb = api.Lookup2(b0, b1, in0.HashOut[i].Limb, in1.HashOut[i].Limb, in2.HashOut[i].Limb, in3.HashOut[i].Limb)
	}
	return out
}

func (hashOut *PoseidonGoldilocksHashOut) ApplyRangeCheck(rangeCheck func(frontend.API, frontend.Rangechecker, frontend.Variable), api frontend.API, rangeChecker frontend.Rangechecker) {
	for _, h := range hashOut.HashOut {
		rangeCheck(api, rangeChecker, h.Limb)
	}
}

func (hashOut *PoseidonGoldilocksHashOut) Make() {
	hashOut.HashOut = make([]goldilocks.GoldilocksVariable, POSEIDON_GOLDILOCKS_HASH_OUT)
}

type MerkleCapVariable []PoseidonGoldilocksHashOut

func SelectHashOutRecursive(api frontend.API, b []frontend.Variable, in []PoseidonGoldilocksHashOut) []PoseidonGoldilocksHashOut {
	if len(in) == 1 {
		return in
	} else if len(in)%4 == 0 {
		two_bits_select := make([]PoseidonGoldilocksHashOut, len(in)/4)
		for i := 0; i < len(two_bits_select); i++ {
			two_bits_select[i] = SelectHashoutLookup2(api, b[0], b[1], in[4*i], in[4*i+1], in[4*i+2], in[4*i+3])
		}
		return SelectHashOutRecursive(api, b[2:], two_bits_select)
	} else {
		// <4 power means len(in) == 2 only
		return []PoseidonGoldilocksHashOut{SelectHashOut(api, b[0], in[1], in[0])}
	}
}

type MerkleProofVariable struct {
	Siblings []PoseidonGoldilocksHashOut
}

type EvalProofVariable struct {
	X []goldilocks.GoldilocksVariable
	Y MerkleProofVariable
}
type FriInitialTreeProofVariable struct {
	EvalsProofs []EvalProofVariable
}

func (proof *FriInitialTreeProofVariable) UnsaltedEval(oracle_index int, poly_index int, salted bool) goldilocks.GoldilocksVariable {
	evals := proof.EvalsProofs[oracle_index].X
	evals = evals[:len(evals)-SaltSize(salted)]
	return evals[poly_index]
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
	CircuitDigest     PoseidonGoldilocksHashOut
}

type PublicInputsVariable []goldilocks.GoldilocksVariable

type FriOpeningBatchVariable struct {
	Values []goldilocks.GoldilocksExtension2Variable
}

type FriOpeningsVariable struct {
	Batches []FriOpeningBatchVariable
}

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

type FriOracleInfo struct {
	NumPolys int
	Blinding bool
}

type FriPolynomialInfo struct {
	OracleIndex     int
	PolynomialIndex int
}

func FromRange(oracle_index int, polynomial_indices Range) []FriPolynomialInfo {
	var vec_poly_info []FriPolynomialInfo
	for i := polynomial_indices.Start; i < polynomial_indices.End; i++ {
		vec_poly_info = append(vec_poly_info, FriPolynomialInfo{OracleIndex: oracle_index, PolynomialIndex: int(i)})
	}
	return vec_poly_info
}

type FriBatchInfo struct {
	Point       goldilocks.GoldilocksExtension2Variable
	Polynomials []FriPolynomialInfo
}

type FriInstanceInfo struct {
	Oracles []FriOracleInfo
	Batches []FriBatchInfo
}

type PlonkOracle struct {
	Index    int
	Blinding bool
}

var CONSTANT_SIGMAS = PlonkOracle{Index: 0, Blinding: false}
var WIRES = PlonkOracle{Index: 1, Blinding: true}
var ZS_PARTIAL_PRODUCTS = PlonkOracle{Index: 2, Blinding: true}
var QUOTIENT = PlonkOracle{Index: 3, Blinding: true}

func SaltSize(salted bool) int {
	if salted {
		return SALT_SIZE
	} else {
		return 0
	}
}
