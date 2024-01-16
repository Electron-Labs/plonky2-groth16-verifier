go build main.go
go install
plonky2-groth16-verifier buildPlonk --common_data ./data/tendermint/common_data.json

plonky2-groth16-verifier provePlonk --plonky2_proof_path ./data/tendermint/proof_with_pis.json --verifier_only_path ./data/tendermint/verifier_only.json --public_inputs_path ./data/tendermint/pub_inputs.json --proving_key_path ./data/pk.bin --r1cs_path ./data/r1cs.bin

plonky2-groth16-verifier verifyPlonk --plonkProofPath ./data/proofP --vkey_path ./data/vk.bin --pub_inputs_path ./data/tendermint/pub_inputs.json

# plonky2-groth16-verifier exportSolPlonk --vkey_path ./data/vk.bin


# plonk proof works with goldilocks/poseidon_bn254 data
# Following error when using tendermint data

# *** output ***
# build called:
#  common data: ./data/tendermint/common_data.json
#  20:38:24 INF compiling circuit
# 20:38:24 INF parsed circuit inputs nbPublic=260 nbSecret=12786
# 20:38:51 INF building constraint builder nbConstraints=20270969
#         Proof gen called:
#  proof: ./data/tendermint/proof_with_pis.json
#  pub_inputs: ./data/tendermint/pub_inputs.json
#  pkey: ./data/pk.bin
#  r1cs: ./data/r1cs.bin
# 21:11:16 ERR error="constraint #8958262 is not satisfied: qL⋅xa + qR⋅xb + qO⋅xc + qM⋅(xaxb) + qC != 0 → 51347595345977486721 + 21888242871839275222246405745257275088548364400416034343351708686050478183040 + 0 + 0 + 0 != 0" nbConstraints=20270969
# 21:11:16 DBG verifier.go:298 > {HashOut_0_Limb: <unsolved>, HashOut_1_Limb: <unsolved>, HashOut_2_Limb: <unsolved>, HashOut_3_Limb: <unsolved>}
# 21:11:16 DBG verifier.go:300 > {PlonkBetas_0_Limb: <unsolved>, PlonkBetas_1_Limb: <unsolved>, PlonkGammas_0_Limb: <unsolved>, PlonkGammas_1_Limb: <unsolved>, PlonkAlphas_0_Limb: <unsolved>, PlonkAlphas_1_Limb: <unsolved>, PlonkZeta_A_Limb: <unsolved>, PlonkZeta_B_Limb: <unsolved>, FriChallenges_FriAlpha_A_Limb: <unsolved>, FriChallenges_FriAlpha_B_Limb: <unsolved>, FriChallenges_FriBetas_0_A_Limb: <unsolved>, FriChallenges_FriBetas_0_B_Limb: <unsolved>, FriChallenges_FriBetas_1_A_Limb: <unsolved>, FriChallenges_FriBetas_1_B_Limb: <unsolved>, FriChallenges_FriBetas_2_A_Limb: <unsolved>, FriChallenges_FriBetas_2_B_Limb: <unsolved>, FriChallenges_FriPowResponse_Limb: <unsolved>, FriChallenges_FriQueryIndices_0: <unsolved>, FriChallenges_FriQueryIndices_1: <unsolved>, FriChallenges_FriQueryIndices_2: <unsolved>, FriChallenges_FriQueryIndices_3: <unsolved>, FriChallenges_FriQueryIndices_4: <unsolved>, FriChallenges_FriQueryIndices_5: <unsolved>, FriChallenges_FriQueryIndices_6: <unsolved>, FriChallenges_FriQueryIndices_7: <unsolved>, FriChallenges_FriQueryIndices_8: <unsolved>, FriChallenges_FriQueryIndices_9: <unsolved>, FriChallenges_FriQueryIndices_10: <unsolved>, FriChallenges_FriQueryIndices_11: <unsolved>, FriChallenges_FriQueryIndices_12: <unsolved>, FriChallenges_FriQueryIndices_13: <unsolved>, FriChallenges_FriQueryIndices_14: <unsolved>, FriChallenges_FriQueryIndices_15: <unsolved>, FriChallenges_FriQueryIndices_16: <unsolved>, FriChallenges_FriQueryIndices_17: <unsolved>, FriChallenges_FriQueryIndices_18: <unsolved>, FriChallenges_FriQueryIndices_19: <unsolved>, FriChallenges_FriQueryIndices_20: <unsolved>, FriChallenges_FriQueryIndices_21: <unsolved>, FriChallenges_FriQueryIndices_22: <unsolved>, FriChallenges_FriQueryIndices_23: <unsolved>, FriChallenges_FriQueryIndices_24: <unsolved>, FriChallenges_FriQueryIndices_25: <unsolved>, FriChallenges_FriQueryIndices_26: <unsolved>, FriChallenges_FriQueryIndices_27: <unsolved>}
# proving error  constraint #8958262 is not satisfied: qL⋅xa + qR⋅xb + qO⋅xc + qM⋅(xaxb) + qC != 0 → 51347595345977486721 + 21888242871839275222246405745257275088548364400416034343351708686050478183040 + 0 + 0 + 0 != 0
