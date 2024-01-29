go build main.go
go install
plonky2-groth16-verifier buildPlonk --common_data ./data/tendermint/common_data.json

# plonky2-groth16-verifier provePlonk --plonky2_proof_path ./data/tendermint/proof_with_pis.json --verifier_only_path ./data/tendermint/verifier_only.json --public_inputs_path ./data/tendermint/pub_inputs.json --proving_key_path ./data/pk.bin --r1cs_path ./data/r1cs.bin

# plonky2-groth16-verifier verifyPlonk --plonkProofPath ./data/proofP --vkey_path ./data/vk.bin --pub_inputs_path ./data/tendermint/pub_inputs.json

# plonky2-groth16-verifier exportSolPlonk --vkey_path ./data/vk.bin