/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var proof_path string
var verifier_only_path string
var public_inputs_path string
var proving_key_path string
var r1cs_path string

// proveCmd represents the prove command
var proveCmd = &cobra.Command{
	Use:   "prove",
	Short: "Generate groth16 proof",
	Long:  `Generates a groth16 proof corresponding to a plonky2 proof and given public inputs.`,
	Run: func(cmd *cobra.Command, args []string) {
		proof, _ := read_proof_from_file(proof_path)
		verifier_only, _ := read_verifier_data_from_file(verifier_only_path)
		public_inputs, _ := read_public_inputs_from_file(public_inputs_path)

		proof_variable := proof.GetVariable()
		vd_variable := verifier_only.GetVariable()
		public_inputs_variable := public_inputs.GetVariable()

		fmt.Println(proof_variable)
		fmt.Println(vd_variable)
		fmt.Println(public_inputs_variable)
	},
}

func init() {
	proveCmd.Flags().StringVarP(&proof_path, "proof_path", "p", "", "JSON File path to plonky2 proof")
	_ = buildCmd.MarkFlagRequired("proof_path")
	proveCmd.Flags().StringVarP(&verifier_only_path, "verifier_only_path", "v", "", "JSON File path to verifier only data")
	_ = buildCmd.MarkFlagRequired("verifier_only_path")
	proveCmd.Flags().StringVarP(&public_inputs_path, "public_inputs_path", "i", "", "JSON File path to public inputs")
	_ = buildCmd.MarkFlagRequired("public_inputs_path")
	proveCmd.Flags().StringVarP(&proving_key_path, "proving_key_path", "k", "", "JSON File path to proving key")
	_ = buildCmd.MarkFlagRequired("proving_key_path")
	proveCmd.Flags().StringVarP(&r1cs_path, "r1cs_path", "r", "", "JSON File path to r1cs")
	_ = buildCmd.MarkFlagRequired("r1cs_path")
	rootCmd.AddCommand(proveCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// proveCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// proveCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
