package verifier

import (
	"github.com/consensys/gnark/frontend"
)

type Runner struct {
	Proof        ProofVariable
	VerifierOnly VerifierOnlyVariable
	CommonData   CommonData
	PubInputs    PublicInputsVariable `gnark:",public"`
}

func (circuit *Runner) Define(api frontend.API) error {
	// verifier := verifier.createVerifier(api, circuit.common_data)
	verifier := createVerifier(api, circuit.CommonData)
	verifier.Verify(circuit.Proof, circuit.VerifierOnly, circuit.PubInputs)
	return nil
}
