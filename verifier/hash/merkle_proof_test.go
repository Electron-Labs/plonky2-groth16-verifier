package hash

import (
	"testing"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/types"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

type VerifyMerkleProofCircuit struct {
	LeafData  []goldilocks.GoldilocksVariable
	LeafIndex frontend.Variable
	MerkleCap types.MerkleCapVariable
	Proof     types.MerkleProofVariable
}

func (circuit *VerifyMerkleProofCircuit) Define(api frontend.API) error {
	leaf_index_bits := api.ToBinary(circuit.LeafIndex, 64)
	VerifyMerkleProofToCap(api, circuit.LeafData, leaf_index_bits, circuit.MerkleCap, circuit.Proof)
	return nil
}

func TestVerifyMerkleProof(t *testing.T) {
	assert := test.NewAssert(t)

	leaf_data := []uint64{4681058518958200638, 11853218359596855979, 1040524120881239799, 5781735197978953753, 6924304365164022147, 240263503171896883, 15801615787590993529, 16226472532925720252, 1672186577990336709, 16833802611292761128, 6771725697693834325, 5128497884664881818, 1646281050279726603}
	leaf_index := 9

	merkle_cap := []string{"2582597339673350977535791112778512319279563543510136642436236239229546141738", "13945976454061663208048138720048435896719276119045044553434024130384674966269"}
	merkle_proof := []string{
		"7875969863634060413400044210918325875604893092267655190620100746004319936533", "21251302547127842287737520631409861730298604750824310355638193714607471652971", "700553277178616703505095854685555494643698627666687102698107722861753096060",
	}
	var circuit VerifyMerkleProofCircuit
	circuit.LeafData = goldilocks.GetGoldilocksVariableArr(leaf_data)
	circuit.LeafIndex = leaf_index
	circuit.MerkleCap = make(types.MerkleCapVariable, len(merkle_cap))
	for i, v := range merkle_cap {
		circuit.MerkleCap[i].HashOut = frontend.Variable(v)
	}
	circuit.Proof.Siblings = make([]types.PoseidonBn254HashOut, len(merkle_proof))
	for i, v := range merkle_proof {
		circuit.Proof.Siblings[i].HashOut = frontend.Variable(v)
	}

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal("failed to compile: ", err)
	}
	t.Log(r1cs.GetNbConstraints())

	var assignment VerifyMerkleProofCircuit
	assignment.LeafData = goldilocks.GetGoldilocksVariableArr(leaf_data)
	assignment.LeafIndex = leaf_index
	assignment.MerkleCap = make(types.MerkleCapVariable, len(merkle_cap))
	for i, v := range merkle_cap {
		assignment.MerkleCap[i].HashOut = frontend.Variable(v)
	}
	assignment.Proof.Siblings = make([]types.PoseidonBn254HashOut, len(merkle_proof))
	for i, v := range merkle_proof {
		assignment.Proof.Siblings[i].HashOut = frontend.Variable(v)
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal("Error in witness: ", err)
	}

	err = r1cs.IsSolved(witness)
	if err != nil {
		t.Fatal("failed to solve: ", err)
	}

	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BN254))
}
