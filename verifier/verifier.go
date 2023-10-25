package verifier

import (
	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

type Proof struct {
}

type CommonData struct {
}

type VerifierOnly struct {
}

type Verifier struct {
	X frontend.Variable
	// proof         Proof
	// common_data   CommonData
	// verifier_only VerifierOnly
	// public_inputs []goldilocks.GoldilocksVariable `gnark:",public"`
}

func (circuit *Verifier) Define(api frontend.API) error {
	rangeChecker := rangecheck.New(api)
	goldilocks.Reduce(api, rangeChecker, circuit.X)
	return nil
}
