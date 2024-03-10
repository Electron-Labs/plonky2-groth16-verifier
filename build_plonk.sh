go build main.go
go install
# plonky2-groth16-verifier buildPlonk --common_data ./data/tendermint/common_data_struct.json
# go run -tags=debug main.go buildPlonk --common_data ./data/tendermint/common_data_struct.json

# plonky2-groth16-verifier provePlonk --plonky2_proof_path ./data/tendermint/proof_with_pis_struct.json --verifier_only_path ./data/tendermint/verifier_only_struct.json --plonky2_public_inputs_path ./data/tendermint/plonky2_pub_inputs_struct.json --gnark_public_inputs_path ./data/tendermint/gnark_pub_inputs_struct.json --proving_key_path ./data/pk.bin --r1cs_path ./data/r1cs.bin

# plonky2-groth16-verifier verifyPlonk --plonkProofPath ./data/proofP --vkey_path ./data/vk.bin --gnark_public_inputs_path ./data/tendermint/gnark_pub_inputs_struct.json

# plonky2-groth16-verifier exportSolPlonk --vkey_path ./data/vk.bin

# osmosis [without recursion]
# *** results [before adding sha]***
# [plonk backend]
# number of constraints: 20669098
# proving time: 156349.328648
# gas usage: 307932

# osmosis [without recursion]
# *** results [with sha]***
# number of constraints: 26690559
# proving time: 167878.632074
# gas usage:


# aggregated [osmosis]
# [plonk backend]
# number of constraints: 18294271
# proving time: 145921.137651
# gas usage: 307932