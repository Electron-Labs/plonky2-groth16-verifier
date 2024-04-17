/*
Copyright © 2023 Electron Labs <utsav@atomlabs.one>
*/
package main

import (
	// #include <stdlib.h>
	"C"

	"bytes"
	"math"
	"math/big"
	"os"

	"github.com/Electron-Labs/plonky2-groth16-verifier/cmd"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier"
	"github.com/consensys/gnark-crypto/ecc"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
)
import (
	"encoding/hex"
	"strconv"
	"time"
)

// must be empty
func main() {
	// commonDataPath := "/home/ubuntu/work/protocol-aggregator/aggregate_data/circuit_data/common_data_struct.json"
	// r1csPath := "data_write/r1cs.bin"
	// provingKeyPath := "data_write/pk.bin"
	// vkeyPath := "data_write/vk.bin"
	// result, msg := BuildPlonkCircuit(
	// 	commonDataPath,
	// 	r1csPath,
	// 	provingKeyPath,
	// 	vkeyPath,
	// )
	// fmt.Println("result", result)
	// fmt.Println("msg", msg)

	// r1csPath := "data_write/r1cs.bin"
	// provingKeyPath := "data_write/pk.bin"
	// vkeyPath := "data_write/vk.bin"
	// plonky2ProofPath := "/home/ubuntu/work/protocol-aggregator/aggregate_data/proof_with_pis_struct.json"
	// verifierOnlyPath := "/home/ubuntu/work/protocol-aggregator/aggregate_data/circuit_data/verifier_only_struct.json"
	// plonky2PublicInputsPath := "/home/ubuntu/work/protocol-aggregator/aggregate_data/public_inputs_struct.json"
	// gnarkPublicInputsPath := "/home/ubuntu/work/protocol-aggregator/aggregate_data/gnark_pub_inputs_struct.json"
	// result, msg, proofHex := GeneratePlonkProof(
	// 	r1csPath,
	// 	provingKeyPath,
	// 	vkeyPath,
	// 	plonky2ProofPath,
	// 	verifierOnlyPath,
	// 	plonky2PublicInputsPath,
	// 	gnarkPublicInputsPath,
	// )
	// fmt.Println("result", result)
	// fmt.Println("msg", msg)
	// fmt.Println("proofHex", proofHex)
}

// go build -o main.so -buildmode=c-shared main.go

func getCStr(str string) *C.char {
	cStr := C.CString(str)
	return cStr
}

//export BuildPlonkCircuit
func BuildPlonkCircuit(commonDataPath string, r1csPath string, provingKeyPath string, vkeyPath string) (result bool, msg *C.char) {
	commonData, err := cmd.ReadCommonDataFromFile(commonDataPath)

	if err != nil {
		return false, getCStr("Failed to read common data file: " + err.Error())
	}
	circuitConstants := cmd.GetCircuitConstants(commonData)
	var myCircuit verifier.Runner

	// Arrays are resized according to circuitConstants before compiling
	myCircuit.Make(circuitConstants, commonData)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &myCircuit)
	if err != nil {
		return false, getCStr("Compile error:" + err.Error())
	}

	srs, err := kzg_bn254.NewSRS(uint64(math.Pow(2, 28)), big.NewInt(-1))
	if err != nil {
		return false, getCStr("SRS error:" + err.Error())
	}

	pk, vk, err := plonk.Setup(ccs, srs)
	if err != nil {
		return false, getCStr("plonk setup error:" + err.Error())
	}

	f_r1cs, err := os.Create(r1csPath)
	if err != nil {
		return false, getCStr("Failed to create r1cs file:" + err.Error())
	}
	ccs.WriteTo(f_r1cs)

	f_pd, _ := os.Create(provingKeyPath)
	if err != nil {
		return false, getCStr("Failed to create pk file:" + err.Error())
	}
	pk.WriteTo(f_pd)

	f_vk, err := os.Create(vkeyPath)
	if err != nil {
		return false, getCStr("Failed to create vk file:" + err.Error())
	}
	vk.WriteTo(f_vk)

	return true, getCStr("success")
}

//export GeneratePlonkProof
func GeneratePlonkProof(r1csPath string, provingKeyPath string, vkeyPath string, plonky2ProofPath string, verifierOnlyPath string, plonky2PublicInputsPath string, gnarkPublicInputsPath string) (result bool, msg *C.char, proofHex *C.char) {
	proofHex = getCStr("0x")

	ccs := plonk.NewCS(ecc.BN254)
	r1csFile, err := os.Open(r1csPath)
	if err != nil {
		return false, getCStr("Error reading CS file:" + err.Error()), proofHex
	}
	ccs.ReadFrom(r1csFile)

	pk := plonk.NewProvingKey(ecc.BN254)
	pkFile, err := os.Open(provingKeyPath)
	if err != nil {
		return false, getCStr("Error reading PK file:" + err.Error()), proofHex
	}
	pk.ReadFrom(pkFile)

	vk := plonk.NewVerifyingKey(ecc.BN254)
	vkFile, err := os.Open(vkeyPath)
	if err != nil {
		return false, getCStr("Error reading VK file:" + err.Error()), proofHex
	}
	vk.ReadFrom(vkFile)

	proof, err := cmd.ReadProofFromFile(plonky2ProofPath)
	if err != nil {
		return false, getCStr("error reading proof file:" + err.Error()), proofHex
	}
	verifierOnly, err := cmd.ReadVerifierDataFromFile(verifierOnlyPath)
	if err != nil {
		return false, getCStr("error reading verifier_only file:" + err.Error()), proofHex
	}
	plonky2PublicInputs, err := cmd.ReadPlonky2PublicInputsFromFile(plonky2PublicInputsPath)
	if err != nil {
		return false, getCStr("error reading plonky2 pub inputs:" + err.Error()), proofHex
	}
	gnarkPublicInputs, err := cmd.ReadGnarkPublicInputsFromFile(gnarkPublicInputsPath)
	if err != nil {
		return false, getCStr("error reading gnark pub inputs:" + err.Error()), proofHex
	}

	proofVariable := proof.GetVariable()
	vdVariable := verifierOnly.GetVariable()
	plonky2PublicInputsVariable := plonky2PublicInputs.GetVariable()
	gnarkPublicInputsVariable := gnarkPublicInputs.GetVariable()

	assignment := &verifier.Runner{
		Proof:            proofVariable,
		VerifierOnly:     vdVariable,
		Plonky2PubInputs: plonky2PublicInputsVariable,
		GnarkPubInputs:   gnarkPublicInputsVariable,
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return false, getCStr("new witness failed:" + err.Error()), proofHex
	}

	start := time.Now()
	proofP, err := plonk.Prove(ccs, pk, witness)
	proofGenTime := getCStr(strconv.Itoa(int(time.Since(start).Seconds())))
	if err != nil {
		return false, getCStr("proving error:" + err.Error()), proofHex
	}

	// verify
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return false, getCStr("new witness failed:" + err.Error()), proofHex
	}
	err = plonk.Verify(proofP, vk, w)
	if err != nil {
		return false, getCStr("verification failed:" + err.Error()), proofHex
	}

	// solidity contract inputs
	var buf bytes.Buffer
	proofP.WriteRawTo(&buf)
	p := proofP.(*plonk_bn254.Proof)
	serializedProof := p.MarshalSolidity()
	proofHex = getCStr(hex.EncodeToString(serializedProof))

	return true, proofGenTime, proofHex
}

func ExportPlonkSolidityVerifier(vkeyPath string, exportPath string) (result bool, msg *C.char) {
	vk := plonk.NewVerifyingKey(ecc.BN254)
	vkFile, err := os.Open(vkeyPath)
	if err != nil {
		return false, getCStr("Error reading VK file:" + err.Error())
	}
	vk.ReadFrom(vkFile)

	f_sol, err := os.Create(exportPath)
	if err != nil {
		return false, getCStr("Error creating Verifier.sol file:" + err.Error())
	}

	err = vk.ExportSolidity(f_sol)
	if err != nil {
		return false, getCStr("Failed to export Solidity Verifier:" + err.Error())
	}
	return true, getCStr("success")
}
