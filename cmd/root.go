/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "plonky2-groth16-verifier",
	Short: "Groth16 wrapper for plonky2 proving scheme",
	Long: `The following tasks are supported as part of the application :
1. (build)Generate circuit for custom plonky2 configs requires plonky2_config.json, common_data
2. (prove)Generate groth16 proof corresponding to a plonky2 proof with pis
3. (verify)Verification of groth16 proof`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
