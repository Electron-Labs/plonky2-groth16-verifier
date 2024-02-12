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

// verifyCmd represents the verifyGroth16 command
var verifyGroth16Cmd = &cobra.Command{
	Use:   "verifyGroth16",
	Short: "Verifies a gnark groth16 proof",
	Long:  `Verifies a gnark groth16 proof`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("verify called:\n proof: %s\n vkey: %s\n pinputs: %s\n", groth16proof_path, vkey_path, gnark_public_inputs_path)
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
		gnark_public_inputs, _ := ReadGnarkPublicInputsFromFile(gnark_public_inputs_path)
		gnark_public_inputs_variable := gnark_public_inputs.GetVariable()
		fmt.Println("gnark_public_inputs: ", gnark_public_inputs)

		// ******************
		// solidity contract inputs
		// var buf bytes.Buffer
		// g16p.WriteRawTo(&buf)
		// p := g16p.(*groth16_bn254.Proof)
		// serializedProof := p.MarshalSolidity()
		// fmt.Println("serializedProof", serializedProof)
		// fmt.Println("public_inputs", public_inputs)
		// ******************

		assignment := &verifier.Runner{
			GnarkPubInputs: gnark_public_inputs_variable,
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
	Use:   "verifyPlonk",
	Short: "Verifies a gnark plonk proof",
	Long:  `Verifies a gnark plonk proof`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("verify called:\n proof: %s\n vkey: %s\n pinputs: %s\n", plonkProofPath, vkey_path, gnark_public_inputs_path)
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

		gnark_public_inputs, _ := ReadGnarkPublicInputsFromFile(gnark_public_inputs_path)
		gnark_public_inputs_variable := gnark_public_inputs.GetVariable()
		fmt.Println("gnark_public_inputs: ", gnark_public_inputs)
		assignment := &verifier.Runner{
			GnarkPubInputs: gnark_public_inputs_variable,
		}

		// ******************
		// solidity contract inputs
		var buf bytes.Buffer
		proofP.WriteRawTo(&buf)
		p := proofP.(*plonk_bn254.Proof)
		serializedProof := p.MarshalSolidity()
		fmt.Println("serializedProof", serializedProof)
		fmt.Println("gnark_public_inputs", gnark_public_inputs)
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
	verifyGroth16Cmd.Flags().StringVarP(&groth16proof_path, "groth16_proof_path", "p", "", "Path to groth16(gnark) proof generated in build phase")
	_ = verifyGroth16Cmd.MarkFlagRequired("groth16_proof_path")
	verifyGroth16Cmd.Flags().StringVarP(&vkey_path, "vkey_path", "v", "", "File to groth16(gnark) vkey  generated in build phase")
	_ = verifyGroth16Cmd.MarkFlagRequired("vkey_path")
	verifyGroth16Cmd.Flags().StringVarP(&gnark_public_inputs_path, "gnark_public_inputs_path", "i", "", "JSON File path to gnark public inputs")
	_ = verifyGroth16Cmd.MarkFlagRequired("gnark_public_inputs_path")
	rootCmd.AddCommand(verifyGroth16Cmd)

	verifyPlonkCmd.Flags().StringVarP(&plonkProofPath, "plonkProofPath", "p", "", "Path to plonk(gnark) proof generated in build phase")
	_ = verifyPlonkCmd.MarkFlagRequired("plonkProofPath")
	verifyPlonkCmd.Flags().StringVarP(&vkey_path, "vkey_path", "v", "", "File to plonk(gnark) vkey  generated in build phase")
	_ = verifyPlonkCmd.MarkFlagRequired("vkey_path")
	verifyPlonkCmd.Flags().StringVarP(&gnark_public_inputs_path, "gnark_public_inputs_path", "i", "", "JSON File path to gnark public inputs")
	_ = verifyPlonkCmd.MarkFlagRequired("gnark_public_inputs_path")
	rootCmd.AddCommand(verifyPlonkCmd)
}
