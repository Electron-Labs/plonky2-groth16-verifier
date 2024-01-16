/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bytes"
	"fmt"
	"os"

	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/spf13/cobra"
)

var plonkProofPath string
var groth16proof_path string
var vkey_path string
var pub_inputs_path string

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verifier gnark proof",
	Long:  `Verifier the groth16 proof`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("verify called:\n proof: %s\n vkey: %s\n pinputs: %s\n", groth16proof_path, vkey_path, pub_inputs_path)
		g16p := groth16.NewProof(ecc.BN254)
		g16p_file, err := os.Open(groth16proof_path)
		if err != nil {
			fmt.Println("g16p file open wrong: ", err)
			os.Exit(1)
		}
		g16p.ReadFrom(g16p_file)

		vk := groth16.NewVerifyingKey(ecc.BN254)
		vkFile, err := os.Open(vkey_path)
		if err != nil {
			fmt.Println("vkFile open wrong: ", err)
			os.Exit(1)
		}
		vk.ReadFrom(vkFile)
		public_inputs, _ := read_public_inputs_from_file(pub_inputs_path)
		public_inputs_variable := public_inputs.GetVariable()
		fmt.Println("public_inputs: ", public_inputs)
		fmt.Println("public_inputs_variable: ", public_inputs_variable)
		assignment := &verifier.Runner{
			PubInputs: public_inputs_variable,
		}
		w, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
		err = groth16.Verify(g16p, vk, w)
		if err != nil {
			fmt.Println("verify wrong: ", err)
			os.Exit(1)
		}
	},
}

// verifyCmd represents the verify with plonk backend command
var verifyPlonkCmd = &cobra.Command{
	Use: "verifyPlonk",
	// Short: "Verifier gnark proof",
	// Long:  `Verifier the groth16 proof`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("verify called:\n proof: %s\n vkey: %s\n pinputs: %s\n", plonkProofPath, vkey_path, pub_inputs_path)
		proofP := plonk.NewProof(ecc.BN254)
		proofPFile, err := os.Open(plonkProofPath)
		if err != nil {
			fmt.Println("proofP file open wrong: ", err)
			os.Exit(1)
		}
		proofP.ReadFrom(proofPFile)

		vk := plonk.NewVerifyingKey(ecc.BN254)
		vkFile, err := os.Open(vkey_path)
		if err != nil {
			fmt.Println("vkFile open wrong: ", err)
			os.Exit(1)
		}
		vk.ReadFrom(vkFile)

		public_inputs, _ := read_public_inputs_from_file(pub_inputs_path)
		public_inputs_variable := public_inputs.GetVariable()
		fmt.Println("public_inputs: ", public_inputs)
		fmt.Println("public_inputs_variable: ", public_inputs_variable)
		assignment := &verifier.Runner{
			PubInputs: public_inputs_variable,
		}

		// ******************
		// solidity contract inputs
		// var (
		// 	a [2]*big.Int
		// 	b [2][2]*big.Int
		// 	c [2]*big.Int
		// )
		// get proof bytes
		const fpSize = 4 * 8
		var buf bytes.Buffer
		proofP.WriteRawTo(&buf)
		// proofBytes := buf.Bytes()
		// proof.Ar, proof.Bs, proof.Krs
		// a[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
		// a[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
		// b[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
		// b[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
		// b[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
		// b[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
		// c[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
		// c[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])

		// fmt.Println("a", a)
		// fmt.Println("b", b)
		// fmt.Println("c", c)
		p := proofP.(*plonk_bn254.Proof)
		serializedProof := p.MarshalSolidity()
		fmt.Println("serializedProof", serializedProof)
		fmt.Println("public_inputs", public_inputs)
		// ******************

		w, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
		err = plonk.Verify(proofP, vk, w)
		// err = groth16.Verify(g16p, vk, w)
		if err != nil {
			fmt.Println("verify wrong: ", err)
			os.Exit(1)
		}
	},
}

func init() {
	verifyCmd.Flags().StringVarP(&groth16proof_path, "groth16_proof_path", "p", "", "Path to groth16(gnark) proof generated in build phase")
	_ = buildCmd.MarkFlagRequired("groth16_proof_path")
	verifyCmd.Flags().StringVarP(&vkey_path, "vkey_path", "v", "", "File to groth16(gnark) vkey  generated in build phase")
	_ = buildCmd.MarkFlagRequired("vkey_path")
	verifyCmd.Flags().StringVarP(&pub_inputs_path, "pub_inputs_path", "i", "", "JSON File path to plonky2 public inputs")
	_ = buildCmd.MarkFlagRequired("pub_inputs_path")
	rootCmd.AddCommand(verifyCmd)

	verifyPlonkCmd.Flags().StringVarP(&plonkProofPath, "plonkProofPath", "p", "", "Path to plonk(gnark) proof generated in build phase")
	_ = buildCmd.MarkFlagRequired("plonkProofPath")
	verifyPlonkCmd.Flags().StringVarP(&vkey_path, "vkey_path", "v", "", "File to plonk(gnark) vkey  generated in build phase")
	_ = buildCmd.MarkFlagRequired("vkey_path")
	verifyPlonkCmd.Flags().StringVarP(&pub_inputs_path, "pub_inputs_path", "i", "", "JSON File path to plonky2 public inputs")
	_ = buildCmd.MarkFlagRequired("pub_inputs_path")
	rootCmd.AddCommand(verifyPlonkCmd)
}
