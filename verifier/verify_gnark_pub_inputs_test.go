package verifier

import (
	"testing"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/types"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

type VerifyGnarkPubInputsCircuit struct {
	Plonky2PubInputs types.Plonky2PublicInputsVariable
	GnarkPubInputs   types.GnarkPublicInputsVariable
}

func (circuit *VerifyGnarkPubInputsCircuit) Define(api frontend.API) error {
	VerifyGnarkPubInputs(api, circuit.Plonky2PubInputs, circuit.GnarkPubInputs)
	return nil
}

func TestVerifyGnarkPubInputs(t *testing.T) {
	assert := test.NewAssert(t)

	type testData struct {
		plonky2PubInputs []uint64
		gnarkPubInputs   []string
	}

	tests := []testData{
		{
			plonky2PubInputs: []uint64{4150607351, 4265771468, 830697859, 4192583370, 1883634718, 3447779555, 2810238612, 3521942354},
			gnarkPubInputs:   []string{"269495255991966090313185470945718789623", "109764766545983247653870208403606619504"},
		},
	}

	nPlonky2PubInputs := 8

	var circuit VerifyGnarkPubInputsCircuit
	circuit.Plonky2PubInputs = make([]goldilocks.GoldilocksVariable, nPlonky2PubInputs)
	circuit.GnarkPubInputs = make([]frontend.Variable, 2)
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal("Error in compiling circuit: ", err)
	}

	for _, t_i := range tests {
		var witness VerifyGnarkPubInputsCircuit
		witness.Plonky2PubInputs = make([]goldilocks.GoldilocksVariable, nPlonky2PubInputs)
		witness.GnarkPubInputs = make([]frontend.Variable, 2)
		for i := 0; i < nPlonky2PubInputs; i++ {
			witness.Plonky2PubInputs[i] = goldilocks.GetGoldilocksVariable(t_i.plonky2PubInputs[i])
		}
		for i := 0; i < 2; i++ {
			witness.GnarkPubInputs[i] = frontend.Variable(t_i.gnarkPubInputs[i])
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
