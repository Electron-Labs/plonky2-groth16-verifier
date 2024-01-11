package poseidonBn254

import (
	"github.com/consensys/gnark/frontend"
)

type Poseidon interface {
	Permute(api frontend.API, state []frontend.Variable) []frontend.Variable
}

type Permutation struct {
	api          frontend.API
	rangeChecker frontend.Rangechecker
	state        []frontend.Variable
	posiedon     Poseidon
}

func NewPermutation(api frontend.API, poseidon Poseidon) Permutation {
	state := make([]frontend.Variable, WIDTH)
	for i := 0; i < WIDTH; i++ {
		state[i] = frontend.Variable(0)
	}
	return Permutation{
		api:      api,
		state:    state,
		posiedon: poseidon,
	}
}

func (permuter *Permutation) Set(idx int, input frontend.Variable) {
	// TODO:
	// if len(inputs) > WIDTH {
	// 	panic("Invalid number of inputs")
	// }

	// for i, v := range inputs {
	// 	permuter.state[i] = v
	// }

	if idx >= WIDTH {
		panic("Invalid index provided")
	}
	permuter.state[idx] = input
}

func (permuter *Permutation) Permute() {
	permuter.state = permuter.posiedon.Permute(permuter.api, permuter.state)
}

func (permuter *Permutation) Squeeze() []frontend.Variable {
	return permuter.state[:RATE]
}
