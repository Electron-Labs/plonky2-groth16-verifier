package verifier

import (
	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark/frontend"
)

type Runner struct {
	Proof        Proof        `gnark:"-"`
	VerifierOnly VerifierOnly `gnark:"-"`
	CommonData   CommonData
	PubInputs    []goldilocks.GoldilocksVariable `gnark:",public"`
}

func (circuit *Runner) Define(api frontend.API) error {
	// verifier := verifier.createVerifier(api, circuit.common_data)
	verifier := createVerifier(api, circuit.CommonData)
	verifier.Verify(circuit.Proof, circuit.VerifierOnly, circuit.PubInputs)
	return nil
}
