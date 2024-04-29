package main

import (
	"fmt"
	"testing"
)

func TestBuildPlonkCircuit(t *testing.T) {
	// build
	nPisBreakdownPath := "data_write/proof/nPisBreakdown.json"
	commonDataPath := "data_write/proof/common_data_struct.json"
	r1csPath := "data_write/plonk/r1cs.bin"
	provingKeyPath := "data_write/plonk/pk.bin"
	vkeyPath := "data_write/plonk/vk.bin"
	result, msg := BuildPlonkCircuit(
		commonDataPath,
		r1csPath,
		provingKeyPath,
		vkeyPath,
		nPisBreakdownPath,
	)
	fmt.Println("result", result)
	fmt.Println("msg", getGoStr(msg))
}

func TestGeneratePlonkProof(t *testing.T) {
	r1csPath := "data_write/plonk/r1cs.bin"
	provingKeyPath := "data_write/plonk/pk.bin"
	vkeyPath := "data_write/plonk/vk.bin"
	plonky2ProofPath := "data_write/proof/proof_with_pis_struct.json"
	verifierOnlyPath := "data_write/proof/verifier_only_struct.json"
	plonky2PublicInputsPath := "data_write/proof/public_inputs_struct.json"
	gnarkPublicInputsPath := "data_write/proof/gnark_pub_inputs_struct.json"
	result, msg, proofHex := GeneratePlonkProof(
		r1csPath,
		provingKeyPath,
		vkeyPath,
		plonky2ProofPath,
		verifierOnlyPath,
		plonky2PublicInputsPath,
		gnarkPublicInputsPath,
	)
	fmt.Println("result", getGoStr(result))
	fmt.Println("msg", getGoStr(msg))
	fmt.Println("proofHex", getGoStr(proofHex))
}

func TestExportPlonkSolidityVerifier(t *testing.T) {
	vkeyPath := "data_write/plonk/vk.bin"
	exportPath := "data_write/plonk/PlonkVerifier.sol"
	result, msg := ExportPlonkSolidityVerifier(
		vkeyPath,
		exportPath,
	)
	fmt.Println("result", result)
	fmt.Println("msg", getGoStr(msg))
}
