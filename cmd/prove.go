/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/spf13/cobra"
)

var plonky2_proof_path string
var verifier_only_path string
var public_inputs_path string
var proving_key_path string
var r1cs_path string
var vk_path string

// proveCmd represents the prove command
var proveCmd = &cobra.Command{
	Use:   "prove",
	Short: "Generate groth16 proof",
	Long:  `Generates a groth16 proof corresponding to a plonky2 proof and given public inputs.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Proof gen called:\n proof: %s\n pub_inputs: %s\n pkey: %s\n r1cs: %s\n",
			plonky2_proof_path, public_inputs_path, proving_key_path, r1cs_path)
		proof, _ := read_proof_from_file(plonky2_proof_path)
		verifier_only, _ := read_verifier_data_from_file(verifier_only_path)
		public_inputs, _ := read_public_inputs_from_file(public_inputs_path)

		proof_variable := proof.GetVariable()
		vd_variable := verifier_only.GetVariable()
		public_inputs_variable := public_inputs.GetVariable()

		assignment := &verifier.Runner{
			Proof:        proof_variable,
			VerifierOnly: vd_variable,
			PubInputs:    public_inputs_variable,
		}

		witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		if err != nil {
			fmt.Println("witness wrong: ", err)
			os.Exit(1)
		}

		// public, _ := witness.Public()

		r1cs := groth16.NewCS(ecc.BN254)
		r1csFile, err := os.Open(r1cs_path)
		if err != nil {
			fmt.Println("r1cs file open wrong: ", err)
			os.Exit(1)
		}
		r1cs.ReadFrom(r1csFile)

		pk := groth16.NewProvingKey(ecc.BN254)
		pkFile, err := os.Open(proving_key_path)
		if err != nil {
			fmt.Println("pkFile open wrong: ", err)
			os.Exit(1)
		}
		pk.ReadFrom(pkFile)

		vk := groth16.NewVerifyingKey(ecc.BN254)
		vkFile, err := os.Open(vk_path)
		if err != nil {
			fmt.Println("vkFile open wrong: ", err)
			os.Exit(1)
		}
		vk.ReadFrom(vkFile)

		g16p, err := groth16.Prove(r1cs, pk, witness)
		if err != nil {
			fmt.Println("proving error ", err)
			os.Exit(1)
		}
		g16p_file, err := os.Create("./data/g16p")
		if err != nil {
			fmt.Println("g16p file open wrong: ", err)
			os.Exit(1)
		}
		g16p.WriteTo(g16p_file)
		if err != nil {
			fmt.Println("prove wrong: ", err)
			os.Exit(1)
		}
	},
}

// provePlonkCmd represents the prove using plonk backend command
var provePlonkCmd = &cobra.Command{
	Use:   "provePlonk",
	Short: "Generate groth16 proof",
	Long:  `Generates a groth16 proof corresponding to a plonky2 proof and given public inputs.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Proof gen called:\n proof: %s\n pub_inputs: %s\n pkey: %s\n r1cs: %s\n",
			plonky2_proof_path, public_inputs_path, proving_key_path, r1cs_path)
		proof, _ := read_proof_from_file(plonky2_proof_path)
		verifier_only, _ := read_verifier_data_from_file(verifier_only_path)
		public_inputs, _ := read_public_inputs_from_file(public_inputs_path)

		proof_variable := proof.GetVariable()
		vd_variable := verifier_only.GetVariable()
		public_inputs_variable := public_inputs.GetVariable()

		assignment := &verifier.Runner{
			Proof:        proof_variable,
			VerifierOnly: vd_variable,
			PubInputs:    public_inputs_variable,
		}

		witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		if err != nil {
			fmt.Println("witness wrong: ", err)
			os.Exit(1)
		}

		// public, _ := witness.Public()

		r1cs := plonk.NewCS(ecc.BN254)
		r1csFile, err := os.Open(r1cs_path)
		if err != nil {
			fmt.Println("r1cs file open wrong: ", err)
			os.Exit(1)
		}
		r1cs.ReadFrom(r1csFile)

		pk := plonk.NewProvingKey(ecc.BN254)
		pkFile, err := os.Open(proving_key_path)
		if err != nil {
			fmt.Println("pkFile open wrong: ", err)
			os.Exit(1)
		}
		pk.ReadFrom(pkFile)

		plonkP, err := plonk.Prove(r1cs, pk, witness)
		if err != nil {
			fmt.Println("proving error ", err)
			os.Exit(1)
		}
		proof_file, err := os.Create("./data/proofP")
		if err != nil {
			fmt.Println("proof file open wrong: ", err)
			os.Exit(1)
		}
		plonkP.WriteTo(proof_file)
		if err != nil {
			fmt.Println("prove wrong: ", err)
			os.Exit(1)
		}
	},
}

func init() {
	proveCmd.Flags().StringVarP(&plonky2_proof_path, "plonky2_proof_path", "p", "", "JSON File path to plonky2 proof")
	_ = buildCmd.MarkFlagRequired("plonky2_proof_path")
	proveCmd.Flags().StringVarP(&verifier_only_path, "verifier_only_path", "v", "", "JSON File path to verifier only data")
	_ = buildCmd.MarkFlagRequired("verifier_only_path")
	proveCmd.Flags().StringVarP(&public_inputs_path, "public_inputs_path", "i", "", "JSON File path to public inputs")
	_ = buildCmd.MarkFlagRequired("public_inputs_path")
	proveCmd.Flags().StringVarP(&proving_key_path, "proving_key_path", "k", "", "JSON File path to proving key")
	_ = buildCmd.MarkFlagRequired("proving_key_path")
	proveCmd.Flags().StringVarP(&r1cs_path, "r1cs_path", "r", "", "JSON File path to r1cs")
	_ = buildCmd.MarkFlagRequired("r1cs_path")
	proveCmd.Flags().StringVarP(&vk_path, "vk_path", "e", "", "JSON File path to vkey")
	_ = buildCmd.MarkFlagRequired("vk_path")
	rootCmd.AddCommand(proveCmd)

	provePlonkCmd.Flags().StringVarP(&plonky2_proof_path, "plonky2_proof_path", "p", "", "JSON File path to plonky2 proof")
	_ = buildCmd.MarkFlagRequired("plonky2_proof_path")
	provePlonkCmd.Flags().StringVarP(&verifier_only_path, "verifier_only_path", "v", "", "JSON File path to verifier only data")
	_ = buildCmd.MarkFlagRequired("verifier_only_path")
	provePlonkCmd.Flags().StringVarP(&public_inputs_path, "public_inputs_path", "i", "", "JSON File path to public inputs")
	_ = buildCmd.MarkFlagRequired("public_inputs_path")
	provePlonkCmd.Flags().StringVarP(&proving_key_path, "proving_key_path", "k", "", "JSON File path to proving key")
	_ = buildCmd.MarkFlagRequired("proving_key_path")
	provePlonkCmd.Flags().StringVarP(&r1cs_path, "r1cs_path", "r", "", "JSON File path to r1cs")
	_ = buildCmd.MarkFlagRequired("r1cs_path")
	rootCmd.AddCommand(provePlonkCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// proveCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// proveCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
