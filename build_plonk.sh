go build main.go
go install
# plonky2-groth16-verifier buildPlonk --common_data ./testdata/tendermint/common_data.json

# plonky2-groth16-verifier provePlonk --plonky2_proof_path ./testdata/tendermint/proof_with_pis.json --verifier_only_path ./testdata/tendermint/verifier_only.json --plonky2_public_inputs_path ./testdata/tendermint/plonky2_pub_inputs.json --gnark_public_inputs_path ./testdata/tendermint/gnark_pub_inputs.json --proving_key_path ./data/pk.bin --r1cs_path ./data/r1cs.bin

# plonky2-groth16-verifier verifyPlonk --plonkProofPath ./data/proofP --vkey_path ./data/vk.bin --gnark_public_inputs_path ./testdata/tendermint/gnark_pub_inputs.json

# plonky2-groth16-verifier exportSolPlonk --vkey_path ./data/vk.bin

# *** results ***
# [plonk backend]
# number of constraints: 20669098
# proving time: 156349.328648
# gas usage: 307932