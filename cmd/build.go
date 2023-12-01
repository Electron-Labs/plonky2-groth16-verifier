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
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/spf13/cobra"
)

var common_data_path string

// buildCmd represents the build command
var buildCmd = &cobra.Command{
	Use:   "build",
	Short: "Build gnark groth16 circuit",
	Long:  `Builds gnark groth16 circuit corresponding to provided common_data and plonky2 config.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("build called:\n common data: %s\n ", common_data_path)

		common_data, err := read_common_data_from_file(common_data_path)
		if err != nil {
			fmt.Println("Failed to read common data file:", err)
			os.Exit(1)
		}
		circuitConstraints := getCircuitConstants(common_data)

		var myCircuit verifier.Runner
		myCircuit.Make(circuitConstraints, common_data)

		r1cs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit)
		pk, vk, _ := groth16.Setup(r1cs)

		f_r1cs, err := os.Create("data/r1cs.bin")
		if err != nil {
			fmt.Println("Failed to create r1cs file:", err)
			os.Exit(1)
		}
		r1cs.WriteTo(f_r1cs)

		f_vk, err := os.Create("data/vk.bin")
		if err != nil {
			fmt.Println("Failed to create vk file:", err)
			os.Exit(1)
		}
		vk.WriteTo(f_vk)

		f_pk, _ := os.Create("data/pk.bin")
		if err != nil {
			fmt.Println("Failed to create pk file:", err)
			os.Exit(1)
		}
		pk.WriteTo(f_pk)

		// proof, _ := read_proof_from_file("./data/goldilocks/proof_with_pis.json")
		// verifier_only, _ := read_verifier_data_from_file("./data/goldilocks/verifier_only.json")
		// public_inputs, _ := read_public_inputs_from_file("./data/goldilocks/pub_inputs.json")

		// proof_variable := proof.GetVariable()
		// vd_variable := verifier_only.GetVariable()
		// public_inputs_variable := public_inputs.GetVariable()

		// assignment := &verifier.Runner{
		// 	Proof:        proof_variable,
		// 	VerifierOnly: vd_variable,
		// 	PubInputs:    public_inputs_variable,
		// }

		// witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		// if err != nil {
		// 	fmt.Println("witness wrong: ", err)
		// 	os.Exit(1)
		// }

		// public, _ := witness.Public()

		// g16p, err := groth16.Prove(r1cs, pk, witness)
		// if err != nil {
		// 	fmt.Println("prove wrong: ", err)
		// 	os.Exit(1)
		// }
		// err = groth16.Verify(g16p, vk, public)
		// if err != nil {
		// 	fmt.Println("verify wrong: ", err)
		// 	os.Exit(1)
		// }

		// load common data from json
		// var myCircuit verifier.Verifier
		// r1cs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit)
		// pk, vk, _ := groth16.Setup(r1cs)
		// assignment := &verifier.Verifier{
		// 	// X: uint(18446744069414584320),
		// }
		// witness, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		// public_witness, _ := witness.Public()

		// proof, _ := groth16.Prove(r1cs, pk, witness)

		// err := groth16.Verify(proof, vk, public_witness)
		// fmt.Print(err == nil)
	},
}

func init() {
	buildCmd.Flags().StringVarP(&common_data_path, "common_data", "d", "", "JSON File path to common data of plonky2 circuit")
	_ = buildCmd.MarkFlagRequired("common_data")
	rootCmd.AddCommand(buildCmd)
}
