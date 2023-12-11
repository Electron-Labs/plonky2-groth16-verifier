package hash

import (
	"testing"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/types"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/consensys/gnark/test"
)

type VerifyMerkleProofCircuit struct {
	LeafData  []goldilocks.GoldilocksVariable
	LeafIndex frontend.Variable
	MerkleCap types.MerkleCapVariable
	Proof     types.MerkleProofVariable
}

func (circuit *VerifyMerkleProofCircuit) Define(api frontend.API) error {
	rangeChecker := rangecheck.New(api)
	leaf_index_bits := api.ToBinary(circuit.LeafIndex, 64)
	VerifyMerkleProofToCap(api, rangeChecker, circuit.LeafData, leaf_index_bits, circuit.MerkleCap, circuit.Proof)
	return nil
}

func TestVerifyMerkleProof(t *testing.T) {
	assert := test.NewAssert(t)

	// leaf_data::[2588089115216973342, 6893304834680000336, 4837607352643158074, 6969160038993304394]
	// leaf_index::4
	// merkle_cap::MerkleCap([HashOut { elements: [3367108721306820270, 4687124867168389637, 10247866295117502739, 9167995917395761542] }])
	// merkle_proof::MerkleProof { siblings: [HashOut { elements: [14412397339032168335, 15798532326344121231, 11460043198242547402, 16510676616743767820] }, HashOut { elements: [12184998889475559148, 14811997910098371392, 13032553179532206176, 2352684615002827561] }, HashOut { elements: [2343746436952691736, 555716703628366696, 17298123600887713158, 3617455914999935308] }] }

	// leaf_data::[13248848056583115022, 11108192005797994995, 18365767924313734462, 3300777344031185801, 12679130458988620991, 6388068640045581874, 0, 0, 14168218603977143798, 7646098699093777243, 16759390691460476703, 6949381026158178250, 11136364229536591104, 5003776057579926307, 0, 0]
	// leaf_index::19
	// merkle_cap::MerkleCap([HashOut { elements: [8866262423865053766, 13242341945743462539, 5940228160815572512, 7741880235118589104] }, HashOut { elements: [4670104104623373566, 17660732589555703363, 6239556977026079794, 4538833753894437311] }, HashOut { elements: [9303516144315242406, 5077605443128212933, 15717164098332827591, 9172171553810081175] }, HashOut { elements: [10392578618540616850, 9036223880735698764, 8761933074747290828, 4601972412203627101] }, HashOut { elements: [2393968428234670657, 13692442835667619088, 12837784471341259074, 1616813255192305386] }, HashOut { elements: [6127857059603958727, 9021139919367081564, 1169725727176792052, 11540745961079804356] }, HashOut { elements: [2745856678510870040, 17250437681511866104, 5107014066285900919, 1507597206157315994] }, HashOut { elements: [1112685397637744635, 11517078872091095566, 3662148105895758727, 16658481704626369403] }])
	// merkle_proof::MerkleProof { siblings: [HashOut { elements: [12857816478506792061, 10217997020342121994, 7508499252116501730, 1924797141091576388] }, HashOut { elements: [12839564860068395184, 12231160221969917201, 12300700918924157415, 14353369543909818633] }] }
	leaf_data := []uint64{13248848056583115022, 11108192005797994995, 18365767924313734462, 3300777344031185801, 12679130458988620991, 6388068640045581874, 0, 0, 14168218603977143798, 7646098699093777243, 16759390691460476703, 6949381026158178250, 11136364229536591104, 5003776057579926307, 0, 0}
	leaf_index := 19
	merkle_cap := [][]uint64{
		{8866262423865053766, 13242341945743462539, 5940228160815572512, 7741880235118589104},
		{4670104104623373566, 17660732589555703363, 6239556977026079794, 4538833753894437311},
		{9303516144315242406, 5077605443128212933, 15717164098332827591, 9172171553810081175},
		{10392578618540616850, 9036223880735698764, 8761933074747290828, 4601972412203627101},
		{2393968428234670657, 13692442835667619088, 12837784471341259074, 1616813255192305386},
		{6127857059603958727, 9021139919367081564, 1169725727176792052, 11540745961079804356},
		{2745856678510870040, 17250437681511866104, 5107014066285900919, 1507597206157315994},
		{1112685397637744635, 11517078872091095566, 3662148105895758727, 16658481704626369403},
	}
	merkle_proof := [][]uint64{
		{12857816478506792061, 10217997020342121994, 7508499252116501730, 1924797141091576388},
		{12839564860068395184, 12231160221969917201, 12300700918924157415, 14353369543909818633},
	}
	var circuit VerifyMerkleProofCircuit
	circuit.LeafData = goldilocks.GetGoldilocksVariableArr(leaf_data)
	circuit.LeafIndex = leaf_index
	circuit.MerkleCap = make(types.MerkleCapVariable, len(merkle_cap))
	for i, v := range merkle_cap {
		circuit.MerkleCap[i].HashOut = goldilocks.GetGoldilocksVariableArr(v)
	}
	circuit.Proof.Siblings = make([]types.HashOutVariable, len(merkle_proof))
	for i, v := range merkle_proof {
		circuit.Proof.Siblings[i].HashOut = goldilocks.GetGoldilocksVariableArr(v)
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
		assignment.MerkleCap[i].HashOut = goldilocks.GetGoldilocksVariableArr(v)
	}
	assignment.Proof.Siblings = make([]types.HashOutVariable, len(merkle_proof))
	for i, v := range merkle_proof {
		assignment.Proof.Siblings[i].HashOut = goldilocks.GetGoldilocksVariableArr(v)
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
