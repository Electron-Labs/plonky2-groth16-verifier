/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier"
	"github.com/consensys/gnark-crypto/ecc"

	// kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/spf13/cobra"
)

var common_data_path string

// buildGroth16Cmd represents the buildGroth16
var buildGroth16Cmd = &cobra.Command{
	Use:   "buildGroth16",
	Short: "Build gnark groth16 circuit",
	Long:  `Builds gnark groth16 circuit corresponding to provided common_data and plonky2 config.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("build called:\n common data: %s\n ", common_data_path)

		common_data, err := ReadCommonDataFromFile(common_data_path)
		if err != nil {
			fmt.Println("Failed to read common data file:", err)
			os.Exit(1)
		}
		circuitConstants := GetCircuitConstants(common_data)

		var myCircuit verifier.Runner

		// Arrays are resized according to circuitConstants before compiling
		myCircuit.Make(circuitConstants, common_data)

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

// buildPlonkCmd represents the buildPlonk
var buildPlonkCmd = &cobra.Command{
	Use:   "buildPlonk",
	Short: "Build gnark plonk circuit",
	Long:  `Builds gnark plonk circuit corresponding to provided common_data and plonky2 config.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("build called:\n common data: %s\n ", common_data_path)

		common_data, err := ReadCommonDataFromFile(common_data_path)
		if err != nil {
			fmt.Println("Failed to read common data file:", err)
			os.Exit(1)
		}
		circuitConstants := GetCircuitConstants(common_data)

		var myCircuit verifier.Runner

		// Arrays are resized according to circuitConstants before compiling
		myCircuit.Make(circuitConstants, common_data)

		ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &myCircuit)
		// r1cs := ccs.(*cs.SparseR1CS)
		// scs := r1cs.(*cs.SparseR1CS)
		// srs, err := test.NewKZGSRS(scs)
		srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
		// srs, err := kzg_bn254.NewSRS(uint64(math.Pow(2, 28)), big.NewInt(-1))
		if err != nil {
			panic(err)
		}
		// pk, vk, _ := plonk.Setup(r1cs, srs)
		pk, vk, _ := plonk.Setup(ccs, srs, srsLagrange)

		f_r1cs, err := os.Create("data/r1cs.bin")
		if err != nil {
			fmt.Println("Failed to create r1cs file:", err)
			os.Exit(1)
		}
		// r1cs.WriteTo(f_r1cs)
		ccs.WriteTo(f_r1cs)

		f_pd, _ := os.Create("data/pk.bin")
		if err != nil {
			fmt.Println("Failed to create pk file:", err)
			os.Exit(1)
		}
		pk.WriteTo(f_pd)

		f_vk, err := os.Create("data/vk.bin")
		if err != nil {
			fmt.Println("Failed to create vk file:", err)
			os.Exit(1)
		}
		vk.WriteTo(f_vk)
	},
}

func init() {
	buildGroth16Cmd.Flags().StringVarP(&common_data_path, "common_data", "d", "", "JSON File path to common data of plonky2 circuit")
	_ = buildGroth16Cmd.MarkFlagRequired("common_data")
	rootCmd.AddCommand(buildGroth16Cmd)

	buildPlonkCmd.Flags().StringVarP(&common_data_path, "common_data", "d", "", "JSON File path to common data of plonky2 circuit")
	_ = buildPlonkCmd.MarkFlagRequired("common_data")
	rootCmd.AddCommand(buildPlonkCmd)
}
