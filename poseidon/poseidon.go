package poseidon

import (
	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark/frontend"
)

type Poseidon interface {
	Permute(api frontend.API, rangeChecker frontend.Rangechecker, inputs []goldilocks.GoldilocksVariable) []goldilocks.GoldilocksVariable
	ConstantExt(api frontend.API, rangeChecker frontend.Rangechecker, in []goldilocks.GoldilocksExtension2Variable, r int) []goldilocks.GoldilocksExtension2Variable
	SboxExt(api frontend.API, rangeChecker frontend.Rangechecker, in goldilocks.GoldilocksExtension2Variable) goldilocks.GoldilocksExtension2Variable
	MdsExt(api frontend.API, rangeChecker frontend.Rangechecker, in []goldilocks.GoldilocksExtension2Variable) []goldilocks.GoldilocksExtension2Variable
	PartialFirstConstantLayerExt(api frontend.API, rangeChecker frontend.Rangechecker, in []goldilocks.GoldilocksExtension2Variable) []goldilocks.GoldilocksExtension2Variable
	MdsPartialLayerInitExt(api frontend.API, rangeChecker frontend.Rangechecker, in []goldilocks.GoldilocksExtension2Variable) []goldilocks.GoldilocksExtension2Variable
	MdsPartialLayerFastExt(api frontend.API, rangeChecker frontend.Rangechecker, in []goldilocks.GoldilocksExtension2Variable, r int) []goldilocks.GoldilocksExtension2Variable
}

type Permutation struct {
	api          frontend.API
	rangeChecker frontend.Rangechecker
	state        []goldilocks.GoldilocksVariable
	posiedon     Poseidon
}

func NewPermutation(api frontend.API, rangeChecker frontend.Rangechecker, poseidon Poseidon) Permutation {
	state := make([]goldilocks.GoldilocksVariable, SPONGE_WIDTH)
	for i := 0; i < SPONGE_WIDTH; i++ {
		state[i] = goldilocks.GoldilocksVariable{Limb: 0}
	}
	return Permutation{
		api:          api,
		rangeChecker: rangeChecker,
		state:        state,
		posiedon:     poseidon,
	}
}

func (permuter *Permutation) Set(inputs []goldilocks.GoldilocksVariable) {
	if len(inputs) > SPONGE_WIDTH {
		panic("Invalid number of inputs")
	}
	for i, v := range inputs {
		permuter.state[i] = v
	}
}

func (permuter *Permutation) Permute() {
	permuter.state = permuter.posiedon.Permute(permuter.api, permuter.rangeChecker, permuter.state)
}

func (permuter *Permutation) Squeeze() []goldilocks.GoldilocksVariable {
	return permuter.state[:SPONGE_RATE]
}
