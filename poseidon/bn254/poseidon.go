package poseidon

import (
	"github.com/consensys/gnark/frontend"
)

type Poseidon interface {
	Permute(api frontend.API, rangeChecker frontend.Rangechecker, inputs []frontend.Variable) []frontend.Variable
}

type Permutation struct {
	api          frontend.API
	rangeChecker frontend.Rangechecker
	state        []frontend.Variable
	posiedon     Poseidon
}

func (permuter *Permutation) Set(inputs []frontend.Variable) {
	if len(inputs) > WIDTH {
		panic("Invalid number of inputs")
	}

	for i, v := range inputs {
		permuter.state[i] = v
	}
}

func (permuter *Permutation) Permute() {
	permuter.state = permuter.posiedon.Permute(permuter.api, permuter.rangeChecker, permuter.state)
}

func (permuter *Permutation) Squeeze() []frontend.Variable {
	return permuter.state[:RATE]
}
