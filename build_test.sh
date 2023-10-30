#!/bin/bash
go build main.go
go install
plonky2-groth16-verifier build --common_data ./data/goldilocks/common_data.json
#
plonky2-groth16-verifier prove --plonky2_proof_path ./data/goldilocks/proof_with_pis.json --verifier_only_path ./data/goldilocks/verifier_only.json --public_inputs_path ./data/goldilocks/pub_inputs.json --proving_key_path ./data/pk.bin --r1cs_path ./data/r1cs.bin --vk_path ./data/vk.bin

plonky2-groth16-verifier verify --groth16_proof_path ./data/g16p --vkey_path ./data/vk.bin --pub_inputs_path ./data/goldilocks/pub_inputs.json
