package poseidonBn254

import (
	"github.com/consensys/gnark/frontend"
)

var C_CONSTANTS []frontend.Variable = GET_C_CONSTANTS()
var S_CONSTANTS []frontend.Variable = GET_S_CONSTANTS()
var M_MATRIX [][]frontend.Variable = GET_M_MATRIX()
var P_MATRIX [][]frontend.Variable = GET_P_MATRIX()

type PoseidonBn254 struct{}

func (poseidon *PoseidonBn254) Permute(api frontend.API, state []frontend.Variable) []frontend.Variable {
	if len(state) != WIDTH {
		panic("Invalid number of inputs")
	}

	poseidon.ark(api, state, 0)
	poseidon.fullRounds(api, state, true)
	poseidon.partialRounds(api, state)
	poseidon.fullRounds(api, state, false)

	return state
}

func (poseidon *PoseidonBn254) ark(api frontend.API, state []frontend.Variable, it int) {
	for i := 0; i < WIDTH; i++ {
		state[i] = api.Add(state[i], C_CONSTANTS[it+i])
	}
}

func (poseidon *PoseidonBn254) exp5(api frontend.API, x frontend.Variable) frontend.Variable {
	aux := x
	x = api.Mul(x, x)
	x = api.Mul(x, x)
	x = api.Mul(x, aux)

	return x
}

func (poseidon *PoseidonBn254) exp5State(api frontend.API, state []frontend.Variable) {
	for i := 0; i < WIDTH; i++ {
		state[i] = poseidon.exp5(api, state[i])
	}
}

func (poseidon *PoseidonBn254) fullRounds(api frontend.API, state []frontend.Variable, first bool) {
	for i := 0; i < FULL_ROUNDS/2-1; i++ {
		poseidon.exp5State(api, state)
		if first {
			poseidon.ark(api, state, (i+1)*WIDTH)
		} else {
			poseidon.ark(
				api,
				state,
				(FULL_ROUNDS/2+1)*WIDTH+PARTIAL_ROUNDS+i*WIDTH,
			)
		}
		poseidon.mix(api, state, M_MATRIX)
	}

	poseidon.exp5State(api, state)
	if first {
		poseidon.ark(api, state, (FULL_ROUNDS/2)*WIDTH)
		poseidon.mix(api, state, P_MATRIX)
	} else {
		poseidon.mix(api, state, M_MATRIX)
	}
}

func (poseidon *PoseidonBn254) partialRounds(api frontend.API, state []frontend.Variable) {
	for i := 0; i < PARTIAL_ROUNDS; i++ {
		state[0] = poseidon.exp5(api, state[0])
		state[0] = api.Add(state[0], C_CONSTANTS[(FULL_ROUNDS/2+1)*WIDTH+i])

		var mul frontend.Variable
		newState0 := frontend.Variable(0)
		for j := 0; j < WIDTH; j++ {
			mul = frontend.Variable(0)
			mul = api.Add(mul, S_CONSTANTS[(WIDTH*2-1)*i+j])
			mul = api.Mul(mul, state[j])
			newState0 = api.Add(newState0, mul)
		}

		for k := 1; k < WIDTH; k++ {
			mul = frontend.Variable(0)
			mul = api.Add(mul, state[0])
			mul = api.Mul(mul, S_CONSTANTS[(WIDTH*2-1)*i+WIDTH+k-1])
			state[k] = api.Add(state[k], mul)
		}

		state[0] = newState0
	}
}

func (poseidon *PoseidonBn254) mix(api frontend.API, state []frontend.Variable, constantMatrix [][]frontend.Variable) {
	result := make([]frontend.Variable, WIDTH)
	for i := 0; i < WIDTH; i++ {
		result[i] = 0
	}

	var mul frontend.Variable
	for i := 0; i < WIDTH; i++ {
		for j := 0; j < WIDTH; j++ {
			mul = frontend.Variable(0)
			mul = api.Add(mul, constantMatrix[j][i])
			mul = api.Mul(mul, state[j])
			result[i] = api.Add(result[i], mul)
		}
	}

	for i := 0; i < WIDTH; i++ {
		state[i] = result[i]
	}
}
