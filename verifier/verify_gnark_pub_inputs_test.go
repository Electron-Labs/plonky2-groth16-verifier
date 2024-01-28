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
			plonky2PubInputs: []uint64{0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 12975357, 0, 12960957, 0},
			gnarkPubInputs:   []string{"232116722419031173675366064768398275761", "62323113525484553733165371844396478664"},
		},
	}

	// to generate gnark pub inputs
	// a.extend([s for s in (12960957).to_bytes(4, "little")]) (create a like this)
	// bytearray(a).hex()
	// take sha
	// b = [s for s in bytes.fromhex(sha)]
	// b = [s for s in bytes.fromhex(sha)]
	// int.from_bytes(bytearray(b[:16]), "little")
	// int.from_bytes(bytearray(b[16:32]), "little")

	nPlonky2PubInputs := 516

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
