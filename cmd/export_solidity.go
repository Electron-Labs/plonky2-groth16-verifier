/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/spf13/cobra"
)

// exportSolGroth16Cmd represents the exportSolGroth16 command
var exportSolGroth16Cmd = &cobra.Command{
	Use:   "exportSolGroth16",
	Short: "Exports Solidity contract for groth16 backend",
	Long:  `Exports VerifyingKey as a Solidity contract for groth16 backend`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("export_solidity called:\n vkey: %s\n ", vkey_path)

		vk := groth16.NewVerifyingKey(ecc.BN254)
		vkFile, err := os.Open(vkey_path)
		if err != nil {
			fmt.Println("vkFile open wrong: ", err)
			os.Exit(1)
		}
		vk.ReadFrom(vkFile)

		f_sol, err := os.Create("data/Verifier.sol")
		if err != nil {
			fmt.Println("Failed to create Verifier.sol file:", err)
			os.Exit(1)
		}
		err = vk.ExportSolidity(f_sol)
		if err != nil {
			fmt.Println("Failed to export Solidity Verifier")
			os.Exit(1)
		} else {
			fmt.Println("Exported succesfully")
		}
	},
}

var exportSolPlonkCmd = &cobra.Command{
	Use:   "exportSolPlonk",
	Short: "Exports Solidity contract for groth16 backend",
	Long:  `Exports VerifyingKey as a Solidity contract for plonk backend`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("export_solidity called:\n vkey: %s\n ", vkey_path)

		vk := plonk.NewVerifyingKey(ecc.BN254)
		vkFile, err := os.Open(vkey_path)
		if err != nil {
			fmt.Println("vkFile open wrong: ", err)
			os.Exit(1)
		}
		vk.ReadFrom(vkFile)

		f_sol, err := os.Create("data/Verifier.sol")
		if err != nil {
			fmt.Println("Failed to create Verifier.sol file:", err)
			os.Exit(1)
		}
		err = vk.ExportSolidity(f_sol)
		if err != nil {
			fmt.Println("Failed to export Solidity Verifier")
			os.Exit(1)
		} else {
			fmt.Println("Exported succesfully")
		}
	},
}

func init() {
	exportSolGroth16Cmd.Flags().StringVarP(&vkey_path, "vkey_path", "v", "", "path to the vk.bin file")
	_ = exportSolGroth16Cmd.MarkFlagRequired("vkey")
	rootCmd.AddCommand(exportSolGroth16Cmd)

	exportSolPlonkCmd.Flags().StringVarP(&vkey_path, "vkey_path", "v", "", "path to the vk.bin file")
	_ = exportSolPlonkCmd.MarkFlagRequired("vkey")
	rootCmd.AddCommand(exportSolPlonkCmd)
}