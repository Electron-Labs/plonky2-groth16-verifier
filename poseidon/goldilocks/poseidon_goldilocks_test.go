package poseidonGoldilocks

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
	poseidon_goldilocks := &PoseidonGoldilocks{}
	outputs := poseidon_goldilocks.Permute(api, rangeChecker, circuit.Inputs)
	for i := 0; i < SPONGE_WIDTH; i++ {
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
			0x3c18a9786cb0b359, 0xc4055e3364a246c3, 0x7953db0ab48808f4, 0xc71603f33a1144ca,
			0xd7709673896996dc, 0x46a84e87642f44ed, 0xd032648251ee0b3c, 0x1c687363b207df62,
			0xdf8565563e8045fe, 0x40f5b37ff4254dae, 0xd070f637b431067c, 0x1792b1c4342109d7,
		}},
		{inputs: []uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, outputs: []uint64{
			0xd64e1e3efc5b8e9e, 0x53666633020aaa47, 0xd40285597c6a8825, 0x613a4f81e81231d2,
			0x414754bfebd051f0, 0xcb1f8980294a023f, 0x6eb2a9e4d54a9d0f, 0x1902bc3af467e056,
			0xf045d5eafdc6021f, 0xe4150f77caaa3be5, 0xc9bfd01d39b50cce, 0x5c0a27fcb0e1459b,
		}},
	}

	var circuit TestPermuteCircuit
	circuit.Inputs = make([]goldilocks.GoldilocksVariable, SPONGE_WIDTH)
	circuit.Outputs = make([]goldilocks.GoldilocksVariable, SPONGE_WIDTH)
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal("Error in compiling circuit: ", err)
	}

	for _, t_i := range tests {
		var witness TestPermuteCircuit
		witness.Inputs = make([]goldilocks.GoldilocksVariable, SPONGE_WIDTH)
		witness.Outputs = make([]goldilocks.GoldilocksVariable, SPONGE_WIDTH)
		for i := 0; i < SPONGE_WIDTH; i++ {
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
