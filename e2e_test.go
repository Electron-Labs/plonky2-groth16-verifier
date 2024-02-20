package main

import (
	"fmt"
	"testing"
)

func TestBuildPlonkCircuit(t *testing.T) {
	commonDataPath := "/home/ubuntu/tendermint-relayer-central-server/aggregation-layer/aggregation_data/circuit_data/common_data_struct.json"
	r1csPath := "data_write/r1cs.bin"
	provingKeyPath := "data_write/pk.bin"
	vkeyPath := "data_write/vk.bin"
	result, msg := BuildPlonkCircuit(
		commonDataPath,
		r1csPath,
		provingKeyPath,
		vkeyPath,
	)
	fmt.Println("result", result)
	fmt.Println("msg", msg)
}

// func TestGeneratePlonkProof(t *testing.T) {
// 	r1csPath := "data_write/r1cs.bin"
// 	provingKeyPath := "data_write/pk.bin"
// 	vkeyPath := "data_write/vk.bin"
// 	plonky2ProofPath := "data/tendermint/proof_with_pis_struct.json"
// 	verifierOnlyPath := "data/tendermint/verifier_only_struct.json"
// 	plonky2PublicInputsPath := "data/tendermint/plonky2_pub_inputs_struct.json"
// 	gnarkPublicInputsPath := "data/tendermint/gnark_pub_inputs_struct.json"
// 	result, msg, proofHex := GeneratePlonkProof(
// 		r1csPath,
// 		provingKeyPath,
// 		vkeyPath,
// 		plonky2ProofPath,
// 		verifierOnlyPath,
// 		plonky2PublicInputsPath,
// 		gnarkPublicInputsPath,
// 	)
// 	fmt.Println("result", result)
// 	fmt.Println("msg", msg)
// 	fmt.Println("proofHex", proofHex)
// }

func TestExportPlonkSolidityVerifier(t *testing.T) {
	vkeyPath := "data_write/vk.bin"
	exportPath := "data_write/PlonkVerifier.sol"
	result, msg := ExportPlonkSolidityVerifier(
		vkeyPath,
		exportPath,
	)

	fmt.Println("result", result)
	fmt.Println("msg", msg)
}
