/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var config_path string
var common_data_path string

// buildCmd represents the build command
var buildCmd = &cobra.Command{
	Use:   "build",
	Short: "Build gnark groth16 circuit",
	Long:  `Builds gnark groth16 circuit corresponding to provided common_data and plonky2 config.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("build called with config at\n %s,\n common data at\n %s ", config_path, common_data_path)
	},
}

func init() {
	buildCmd.Flags().StringVarP(&config_path, "config", "c", "", "JSON File path to plonky2 config")
	_ = buildCmd.MarkFlagRequired("config")
	buildCmd.Flags().StringVarP(&common_data_path, "common_data", "d", "", "JSON File path to common data of plonky2 circuit")
	_ = buildCmd.MarkFlagRequired("common_data")
	rootCmd.AddCommand(buildCmd)
}
