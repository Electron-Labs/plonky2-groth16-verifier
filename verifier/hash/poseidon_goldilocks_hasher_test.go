package hash

import (
	"testing"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	poseidonGoldilocks "github.com/Electron-Labs/plonky2-groth16-verifier/poseidon/goldilocks"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/consensys/gnark/test"
)

type TestPoseidonGoldilocksHashNoPad struct {
	Inputs []goldilocks.GoldilocksVariable
}

// only prints the output; doesn't verify it
func (circuit *TestPoseidonGoldilocksHashNoPad) Define(api frontend.API) error {
	rangeChecker := rangecheck.New(api)
	poseidon_goldilocks := &poseidonGoldilocks.PoseidonGoldilocks{}
	hasher := NewPoseidonGoldilocksHasher(api, rangeChecker, poseidon_goldilocks)
	computedHash := hasher.HashNoPad(circuit.Inputs)
	api.Println("computedHash 0", computedHash.HashOut[0].Limb)
	return nil
}

func TestPoseidonGoldilocksHashNoPadFunction(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit TestPoseidonGoldilocksHashNoPad

	// when the the input is empty
	circuit.Inputs = goldilocks.GetGoldilocksVariableArr([]uint64{})

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal("failed to compile: ", err)
	}

	t.Log("NbConstraints: ", r1cs.GetNbConstraints())

	var assignment TestPoseidonGoldilocksHashNoPad
	assignment.Inputs = goldilocks.GetGoldilocksVariableArr([]uint64{})

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal("Error in witness: ", err)
	}

	err = r1cs.IsSolved(witness)
	if err != nil {
		t.Fatal("failed to solve: ", err)
	}

	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BN254))
}
