#!/bin/bash
go build main.go
go install
plonky2-groth16-verifier build --common_data ./data/goldilocks/common_data.json
#
# plonky2-groth16-verifier prove --proof_path ./data/goldilocks/proof_with_pis.json --verifier_only_path ./data/goldilocks/verifier_only.json --public_inputs_path ./data/goldilocks/pub_inputs.json --proving_key_path ./data/goldilocks/pub_inputs.json --r1cs_path ./data/goldilocks/pub_inputs.json
