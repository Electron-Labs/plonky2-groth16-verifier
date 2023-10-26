package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier"
)

func read_common_data_from_file(path string) (verifier.CommonData, error) {
	jsonCommonData, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println("Error reading JSON file:", err)
		return verifier.CommonData{}, err
	}

	var commonData verifier.CommonData

	if err := json.Unmarshal(jsonCommonData, &commonData); err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return verifier.CommonData{}, err
	}
	return commonData, nil
}

func read_verifier_data_from_file(path string) (verifier.VerifierOnly, error) {
	jsonVerifierData, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println("Error reading verifier only json file:", err)
		return verifier.VerifierOnly{}, err
	}
	var verifier_only verifier.VerifierOnly
	if err := json.Unmarshal(jsonVerifierData, &verifier_only); err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return verifier.VerifierOnly{}, err
	}
	return verifier_only, nil
}

func read_proof_from_file(path string) (verifier.Proof, error) {
	jsonProofData, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println("Error reading verifier only json file:", err)
		return verifier.Proof{}, err
	}
	var proof verifier.Proof
	if err := json.Unmarshal(jsonProofData, &proof); err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return verifier.Proof{}, err
	}
	return proof, nil
}

func read_public_inputs_from_file(path string) (verifier.PublicInputs, error) {
	jsonPublicInputsData, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println("Error reading verifier only json file:", err)
		return verifier.PublicInputs{}, err
	}
	var pub_inputs verifier.PublicInputs
	if err := json.Unmarshal(jsonPublicInputsData, &pub_inputs); err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return verifier.PublicInputs{}, err
	}
	return pub_inputs, nil
}
