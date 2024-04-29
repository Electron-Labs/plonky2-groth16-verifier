/*
Copyright © 2023 Electron Labs <utsav@atomlabs.one>
*/
package main

import (
	// #include <stdlib.h>
	"C"

	"os"

	"github.com/Electron-Labs/plonky2-groth16-verifier/cmd"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)
import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

// must be empty
func main() {
}

func getCStr(str string) *C.char {
	cStr := C.CString(str)
	return cStr
}

func getGoStr(str *C.char) string {
	goStr := C.GoString(str)
	return goStr
}

func BuildPlonkCircuit(commonDataPath string, r1csPath string, provingKeyPath string, vkeyPath string, nPisBreakdownPath string) (result bool, msg *C.char) {
	nPisBreakdown, err := cmd.ReadNPisBreakdownFromFile(nPisBreakdownPath)
	if err != nil {
		return false, getCStr("Failed to read NPisBreakdown file: " + err.Error())
	}

	commonData, err := cmd.ReadCommonDataFromFile(commonDataPath)
	if err != nil {
		return false, getCStr("Failed to read common data file: " + err.Error())
	}
	circuitConstants := cmd.GetCircuitConstants(commonData)
	var myCircuit verifier.Runner

	// Arrays are resized according to circuitConstants before compiling
	myCircuit.Make(circuitConstants, commonData, nPisBreakdown)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &myCircuit)
	if err != nil {
		return false, getCStr("Compile error:" + err.Error())
	}

	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		return false, getCStr("SRS error:" + err.Error())
	}

	// srs, err := kzg_bn254.NewSRS(uint64(math.Pow(2, 28)), big.NewInt(-1))
	// if err != nil {
	// 	return false, getCStr("SRS error:" + err.Error())
	// }
	// pk, vk, err := plonk.Setup(ccs, srs)

	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		return false, getCStr("plonk setup error:" + err.Error())
	}

	f_r1cs, err := os.Create(r1csPath)
	if err != nil {
		return false, getCStr("Failed to create r1cs file:" + err.Error())
	}
	ccs.WriteTo(f_r1cs)

	f_pd, err := os.Create(provingKeyPath)
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

func BuildGroth16Circuit(commonDataPath string, r1csPath string, provingKeyPath string, vkeyPath string, nPisBreakdownPath string) (result bool, msg *C.char) {
	nPisBreakdown, err := cmd.ReadNPisBreakdownFromFile(nPisBreakdownPath)
	if err != nil {
		return false, getCStr("Failed to read NPisBreakdown file: " + err.Error())
	}

	commonData, err := cmd.ReadCommonDataFromFile(commonDataPath)

	if err != nil {
		return false, getCStr("Failed to read common data file: " + err.Error())
	}
	circuitConstants := cmd.GetCircuitConstants(commonData)
	var myCircuit verifier.Runner

	// Arrays are resized according to circuitConstants before compiling
	myCircuit.Make(circuitConstants, commonData, nPisBreakdown)

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit)
	if err != nil {
		return false, getCStr("Compile error:" + err.Error())
	}
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		return false, getCStr("Groth16 setup error:" + err.Error())
	}

	f_r1cs, err := os.Create("data_write/r1cs.bin")
	if err != nil {
		return false, getCStr("Failed to create r1cs file:" + err.Error())
	}
	r1cs.WriteTo(f_r1cs)

	f_vk, err := os.Create("data_write/vk.bin")
	if err != nil {
		return false, getCStr("Failed to create vk file:" + err.Error())
	}
	vk.WriteTo(f_vk)

	f_pk, err := os.Create("data_write/pk.bin")
	if err != nil {
		return false, getCStr("Failed to create pk file:" + err.Error())
	}
	pk.WriteTo(f_pk)

	return true, getCStr("success")
}

//export GenerateGroth16Proof
func GenerateGroth16Proof(r1csPath string, provingKeyPath string, vkeyPath string, plonky2ProofPath string, verifierOnlyPath string, plonky2PublicInputsPath string, gnarkPublicInputsPath string) (result *C.char, msg *C.char, proofHex *C.char) {
	proofHex = getCStr("0x")
	falseCString := getCStr("false")
	trueCString := getCStr("true")

	r1cs := groth16.NewCS(ecc.BN254)
	r1csFile, err := os.Open(r1csPath)
	if err != nil {
		return falseCString, getCStr("r1cs file open wrong:" + err.Error()), proofHex
	}
	r1cs.ReadFrom(r1csFile)

	pk := groth16.NewProvingKey(ecc.BN254)
	pkFile, err := os.Open(provingKeyPath)
	if err != nil {
		os.Exit(1)
	}
	pk.ReadFrom(pkFile)

	vk := groth16.NewVerifyingKey(ecc.BN254)
	vkFile, err := os.Open(vkeyPath)
	if err != nil {
		os.Exit(1)
	}
	vk.ReadFrom(vkFile)

	proof, err := cmd.ReadProofFromFile(plonky2ProofPath)
	if err != nil {
		return falseCString, getCStr("error reading proof file:" + err.Error()), proofHex
	}
	verifierOnly, err := cmd.ReadVerifierDataFromFile(verifierOnlyPath)
	if err != nil {
		return falseCString, getCStr("error reading verifier_only file:" + err.Error()), proofHex
	}
	plonky2PublicInputs, err := cmd.ReadPlonky2PublicInputsFromFile(plonky2PublicInputsPath)
	if err != nil {
		return falseCString, getCStr("error reading plonky2 pub inputs:" + err.Error()), proofHex
	}
	gnarkPublicInputs, err := cmd.ReadGnarkPublicInputsFromFile(gnarkPublicInputsPath)
	if err != nil {
		return falseCString, getCStr("error reading gnark pub inputs:" + err.Error()), proofHex
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
		return falseCString, getCStr("new witness failed:" + err.Error()), proofHex
	}

	proverOption := backend.WithProverHashToFieldFunction(sha256.New())
	start := time.Now()
	g16P, err := groth16.Prove(r1cs, pk, witness, proverOption)
	if err != nil {
		return falseCString, getCStr("proving error:" + err.Error()), proofHex
	}
	proofGenTime := getCStr(strconv.Itoa(int(time.Since(start).Seconds())))

	// verify
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return falseCString, getCStr("new witness failed:" + err.Error()), proofHex
	}
	verifierOption := backend.WithVerifierHashToFieldFunction(sha256.New())
	err = groth16.Verify(g16P, vk, w, verifierOption)
	if err != nil {
		return falseCString, getCStr("verification failed:" + err.Error()), proofHex
	}

	// TODO:
	// solidity contract inputs
	// get proof bytes
	const fpSize = 4 * 8
	var buf bytes.Buffer
	g16P.WriteRawTo(&buf)
	proofBytes := buf.Bytes()

	var (
		a [2]*big.Int
		b [2][2]*big.Int
		c [2]*big.Int
	)

	// proof.Ar, proof.Bs, proof.Krs
	a[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	a[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	b[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	b[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	b[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	b[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	c[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	c[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])

	fmt.Println("a", a)
	fmt.Println("b", b)
	fmt.Println("c", c)

	p := g16P.(*groth16_bn254.Proof)

	CommitmentPokX := new(big.Int)
	CommitmentPokXRegular := p.CommitmentPok.X.BigInt(CommitmentPokX)
	CommitmentPokY := new(big.Int)
	CommitmentPokYRegular := p.CommitmentPok.Y.BigInt(CommitmentPokY)

	fmt.Println("CommitmentPokXRegular", CommitmentPokXRegular)
	fmt.Println("CommitmentPokYRegular", CommitmentPokYRegular)

	CommitmentX := new(big.Int)
	CommitmentXRegular := p.Commitments[0].X.BigInt(CommitmentX)
	CommitmentY := new(big.Int)
	CommitmentYRegular := p.Commitments[0].Y.BigInt(CommitmentY)

	fmt.Println("CommitmentXRegular", CommitmentXRegular)
	fmt.Println("CommitmentYRegular", CommitmentYRegular)

	//  refer: https://github.com/ConsenSys/gnark-tests/blob/47873ce8e146c1f74477a15972ec63cbfd73c888/solidity/solidity_test.go#L81
	// _w, ok := w.Vector().(fr_bn254.Vector)
	// // if !ok {
	// // 	return witness.ErrInvalidWitness
	// // }
	// _proof := g16P.(*groth16_bn254.Proof)

	// var buf bytes.Buffer
	// g16P.WriteRawTo(&buf)
	// p := g16P.(*groth16_bn254.Proof)
	// serializedProof := p.MarshalSolidity()
	// proofHex = getCStr(hex.EncodeToString(serializedProof))

	return trueCString, proofGenTime, proofHex
}

func GeneratePlonkProof(r1csPath string, provingKeyPath string, vkeyPath string, plonky2ProofPath string, verifierOnlyPath string, plonky2PublicInputsPath string, gnarkPublicInputsPath string) (result *C.char, msg *C.char, proofHex *C.char) {
	proofHex = getCStr("0x")
	falseCString := getCStr("false")
	trueCString := getCStr("true")

	ccs := plonk.NewCS(ecc.BN254)
	r1csFile, err := os.Open(r1csPath)
	if err != nil {
		return falseCString, getCStr("Error reading CS file:" + err.Error()), proofHex
	}
	ccs.ReadFrom(r1csFile)

	pk := plonk.NewProvingKey(ecc.BN254)
	pkFile, err := os.Open(provingKeyPath)
	if err != nil {
		return falseCString, getCStr("Error reading PK file:" + err.Error()), proofHex
	}
	pk.ReadFrom(pkFile)

	vk := plonk.NewVerifyingKey(ecc.BN254)
	vkFile, err := os.Open(vkeyPath)
	if err != nil {
		return falseCString, getCStr("Error reading VK file:" + err.Error()), proofHex
	}
	vk.ReadFrom(vkFile)

	proof, err := cmd.ReadProofFromFile(plonky2ProofPath)
	if err != nil {
		return falseCString, getCStr("error reading proof file:" + err.Error()), proofHex
	}
	verifierOnly, err := cmd.ReadVerifierDataFromFile(verifierOnlyPath)
	if err != nil {
		return falseCString, getCStr("error reading verifier_only file:" + err.Error()), proofHex
	}
	plonky2PublicInputs, err := cmd.ReadPlonky2PublicInputsFromFile(plonky2PublicInputsPath)
	if err != nil {
		return falseCString, getCStr("error reading plonky2 pub inputs:" + err.Error()), proofHex
	}
	gnarkPublicInputs, err := cmd.ReadGnarkPublicInputsFromFile(gnarkPublicInputsPath)
	if err != nil {
		return falseCString, getCStr("error reading gnark pub inputs:" + err.Error()), proofHex
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
		return falseCString, getCStr("new witness failed:" + err.Error()), proofHex
	}

	start := time.Now()
	proofP, err := plonk.Prove(ccs, pk, witness)
	proofGenTime := getCStr(strconv.Itoa(int(time.Since(start).Seconds())))
	if err != nil {
		return falseCString, getCStr("proving error:" + err.Error()), proofHex
	}

	// verify
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return falseCString, getCStr("new witness failed:" + err.Error()), proofHex
	}
	err = plonk.Verify(proofP, vk, w)
	if err != nil {
		return falseCString, getCStr("verification failed:" + err.Error()), proofHex
	}

	// solidity contract inputs
	var buf bytes.Buffer
	proofP.WriteRawTo(&buf)
	p := proofP.(*plonk_bn254.Proof)
	serializedProof := p.MarshalSolidity()
	proofHex = getCStr(hex.EncodeToString(serializedProof))

	return trueCString, proofGenTime, proofHex
}

func ExportGroth16SolidityVerifier(vkeyPath string, exportPath string) (result bool, msg *C.char) {
	vk := groth16.NewVerifyingKey(ecc.BN254)
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
