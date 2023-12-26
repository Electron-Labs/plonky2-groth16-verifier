package poseidon2

import (
	"testing"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/consensys/gnark/test"
)

type TestPermuteCircuit struct {
	Inputs  []goldilocks.GoldilocksVariable
	Outputs []goldilocks.GoldilocksVariable
}

func (circuit *TestPermuteCircuit) Define(api frontend.API) error {
	rangeChecker := rangecheck.New(api)
	poseidon2_goldilocks := &Poseidon2Goldilocks{}
	outputs := poseidon2_goldilocks.Permute(api, rangeChecker, circuit.Inputs)
	for i := 0; i < WIDTH; i++ {
		api.AssertIsEqual(outputs[i].Limb, circuit.Outputs[i].Limb)
	}
	return nil
}

func TestPermute(t *testing.T) {
	assert := test.NewAssert(t)

	type testData struct {
		inputs  []uint64
		outputs []uint64
	}

	tests := []testData{
		{inputs: []uint64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, outputs: []uint64{
			0x258f5d724d96657c, 0xe4705cb2bdf352a9, 0x1c7a64d9a419b8d1, 0x85ea4b31a2a80852,
			0x1c3905a5ad453c05, 0xe189827abb2b2fd7, 0x19f188debb97ed74, 0x058a27827177cb53,
			0x0d5e4495f37fe126, 0x04d49ddd80ef3a86, 0x76249c9cf812fde9, 0xba5ed5def4919125,
		}},
		{inputs: []uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, outputs: []uint64{
			0xc928fbab20588837, 0x8f58371184fbe53f, 0x413421022574c26f, 0xcb64c3b646f0a5ea,
			0xc2d9ae62a5d6c49b, 0xfdb53a50adebbb2b, 0x5e79cc08e39887e3, 0x542ef4595fb6bd26,
			0x4b1b01c646a4059b, 0xcf95ccb2224efb91, 0x436dfb5c41b87e7d, 0x7c7fb3bba5883d48,
		}},
	}

	var circuit TestPermuteCircuit
	circuit.Inputs = make([]goldilocks.GoldilocksVariable, WIDTH)
	circuit.Outputs = make([]goldilocks.GoldilocksVariable, WIDTH)
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal("Error in compiling circuit: ", err)
	}

	for _, t_i := range tests {
		var witness TestPermuteCircuit
		witness.Inputs = make([]goldilocks.GoldilocksVariable, WIDTH)
		witness.Outputs = make([]goldilocks.GoldilocksVariable, WIDTH)
		for i := 0; i < WIDTH; i++ {
			witness.Inputs[i] = goldilocks.GetGoldilocksVariable(t_i.inputs[i])
			witness.Outputs[i] = goldilocks.GetGoldilocksVariable(t_i.outputs[i])
		}

		w, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal("Error in witness: ", err, "\n test: ", t_i)
		}
		err = r1cs.IsSolved(w)
		if err != nil {
			t.Fatal("Circuit not solved: ", err, "\n test: ", t_i)
		}
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254))
	}
}
