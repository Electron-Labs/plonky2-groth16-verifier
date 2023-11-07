package verifier

import (
	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark/frontend"
)

type Challenger struct {
	spongeState  goldilocks.Permutation
	inputBuffer  []goldilocks.GoldilocksVariable
	inputIdx     int
	outputBuffer []goldilocks.GoldilocksVariable
	outputIdx    int
}

func NewChallenger(api frontend.API, rangeChecker frontend.Rangechecker) Challenger {
	permutation := goldilocks.NewPermutation(api, rangeChecker)
	inputBuffer := make([]goldilocks.GoldilocksVariable, goldilocks.SPONGE_RATE)
	outputBuffer := make([]goldilocks.GoldilocksVariable, goldilocks.SPONGE_RATE)
	return Challenger{
		spongeState:  permutation,
		inputBuffer:  inputBuffer,
		inputIdx:     0,
		outputBuffer: outputBuffer,
		outputIdx:    0,
	}
}

func (challenger *Challenger) ObserveElement(elm goldilocks.GoldilocksVariable) {
	challenger.inputBuffer[challenger.inputIdx] = elm
	challenger.inputIdx += 1
	if challenger.inputIdx == goldilocks.SPONGE_RATE {
		challenger.duplex()
	}
}

func (challenger *Challenger) ObserveExtensionElement(elm goldilocks.GoldilocksExtension2Variable) {
	challenger.ObserveElement(elm.A)
	challenger.ObserveElement(elm.B)
}

func (challenger *Challenger) ObserveElements(elms []goldilocks.GoldilocksVariable) {
	for _, elm := range elms {
		challenger.ObserveElement(elm)
	}
}

func (challenger *Challenger) ObserveExtensionElements(elms []goldilocks.GoldilocksExtension2Variable) {
	for _, elm := range elms {
		challenger.ObserveExtensionElement(elm)
	}
}

func (challenger *Challenger) ObserveHash(hash HashOutVariable) {
	for _, elm := range hash.HashOut {
		challenger.ObserveElement(elm)
	}
}

func (challenger *Challenger) ObserveCap(cap MerkleCapVariable) {
	for _, hash := range cap {
		challenger.ObserveHash(hash)
	}
}

func (challenger *Challenger) ObserveOpenings(openings FriOpeningsVariable) {
	for _, v := range openings.Batches {
		challenger.ObserveExtensionElements(v.Values)
	}
}

func (challenger *Challenger) GetChallenge() goldilocks.GoldilocksVariable {
	if challenger.outputIdx == 0 || challenger.inputIdx != 0 {
		challenger.duplex()
	}

	challenger.outputIdx -= 1
	return challenger.outputBuffer[challenger.outputIdx]
}

func (challenger *Challenger) GetNChallenges(n int) []goldilocks.GoldilocksVariable {
	challenges := make([]goldilocks.GoldilocksVariable, n)
	for i := 0; i < n; i++ {
		challenges[i] = challenger.GetChallenge()
	}
	return challenges
}

func (challenger *Challenger) GetExtensionChallenge() goldilocks.GoldilocksExtension2Variable {
	challenges := challenger.GetNChallenges(2)
	return goldilocks.GoldilocksExtension2Variable{
		A: challenges[0],
		B: challenges[1],
	}
}

func (challenger *Challenger) duplex() {
	challenger.spongeState.Set(challenger.inputBuffer[:challenger.inputIdx])
	challenger.spongeState.Permute()
	for i, v := range challenger.spongeState.Squeeze() {
		challenger.outputBuffer[i] = v
	}
	challenger.inputIdx = 0
	challenger.outputIdx = goldilocks.SPONGE_RATE
}
