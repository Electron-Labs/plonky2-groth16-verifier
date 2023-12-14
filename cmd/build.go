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

		// Arrays are resized according to circuitConstants before compiling
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
	},
}

func init() {
	buildCmd.Flags().StringVarP(&common_data_path, "common_data", "d", "", "JSON File path to common data of plonky2 circuit")
	_ = buildCmd.MarkFlagRequired("common_data")
	rootCmd.AddCommand(buildCmd)
}
