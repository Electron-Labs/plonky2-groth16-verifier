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
		fmt.Printf("build called with common data at %s\n ", common_data_path)
		cd, _ := read_common_data_from_file(common_data_path)

		myCircuit := verifier.Runner{
			CommonData: cd,
		}

		r1cs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit)
		pk, vk, _ := groth16.Setup(r1cs)

		fmt.Println(r1cs)
		fmt.Println(pk)
		fmt.Println(vk)

		f_r1cs, _ := os.Create("data/r1cs")
		r1cs.WriteTo(f_r1cs)

		f_vk, _ := os.Create("data/vk")
		vk.WriteTo(f_vk)

		f_pk, _ := os.Create("data/pk")
		pk.WriteTo(f_pk)

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
