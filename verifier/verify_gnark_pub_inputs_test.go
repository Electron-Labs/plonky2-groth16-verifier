package verifier

import (
	"testing"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/types"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

type VerifyGnarkPubInputsCircuit struct {
	Plonky2PubInputs types.Plonky2PublicInputsVariable
	GnarkPubInputs   types.GnarkPublicInputsVariable
}

func (circuit *VerifyGnarkPubInputsCircuit) Define(api frontend.API) error {
	VerifyGnarkPubInputs(api, circuit.Plonky2PubInputs, circuit.GnarkPubInputs)
	return nil
}

func TestVerifyGnarkPubInputs(t *testing.T) {
	assert := test.NewAssert(t)

	type testData struct {
		plonky2PubInputs []uint64
		shaInputs        []string
		gnarkPubInputs   []string
	}

	tests := []testData{
		{
			plonky2PubInputs: []uint64{3036297269, 3729460488, 1373751520, 2373291176, 1947646873, 3909450913, 1206480117, 336951175},
			shaInputs:        []string{"9084185715006940422658704026585287580391421154643812857914020806835524220981"},
			gnarkPubInputs:   []string{"69458699013557716879474377907652415629", "120707198893087350479416332617860524982"},
		},
		{
			plonky2PubInputs: []uint64{3036297269, 3729460488, 1373751520, 2373291176, 1947646873, 3909450913, 1206480117, 336951175, 2720110794, 2114321473, 3821511138, 3517458455, 528144481, 2576296058, 500394431, 496357583, 4101001027, 3576004974, 3212868032, 2529596303, 3955585144, 0, 0, 0, 4101001027, 3576004974, 3212868032, 2529596303, 3955585144, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3739620624, 2804118515, 1263138639, 2024767662, 489194404, 2304823440, 696920222, 182805790, 2678542657, 3334753172, 1223075189, 1627896871, 4125019138, 3602076944, 2966183799, 733061911, 1707020993, 1295438072, 3313787126, 2889178860, 3740358570, 3946086764, 1098440719, 1166121, 30, 0, 0, 0, 0, 0, 0, 0, 781907759, 1020975199, 3905557141, 722854541, 88172236, 2255874416, 122495187, 206766913},
			shaInputs:        []string{"9084185715006940422658704026585287580391421154643812857914020806835524220981", "13381773968656823820357727491411722864679455314318075077371762305238028097738", "1346015875558036475662744592749572718782630088515", "1346015875558036475662744592749572718782630088515", "0", "0", "4928434353220978894980315525185218579247881115292094220522030114827800024336", "19763310042898566410194448523282671815990392751360949122385229118071057633601", "31438566862468520449502523460126511955653205887911167763712650116134277825", "30", "5574424947780291050509432702569741144052003379572399091134069995324124624687"},
			gnarkPubInputs:   []string{"136424942014872077207467300767004717562", "78819473150836869372504483739227488922"},
		},
	}

	for i, t_i := range tests {
		nPlonky2PubInputs := len(tests[i].plonky2PubInputs)
		nGnarkPubInputs := len(tests[i].gnarkPubInputs)

		var circuit VerifyGnarkPubInputsCircuit
		circuit.Plonky2PubInputs = make([]goldilocks.GoldilocksVariable, nPlonky2PubInputs)
		circuit.GnarkPubInputs = make([]frontend.Variable, nGnarkPubInputs)
		r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			t.Fatal("Error in compiling circuit: ", err)
		}

		var witness VerifyGnarkPubInputsCircuit
		witness.Plonky2PubInputs = make([]goldilocks.GoldilocksVariable, nPlonky2PubInputs)
		witness.GnarkPubInputs = make([]frontend.Variable, nGnarkPubInputs)
		for i := 0; i < nPlonky2PubInputs; i++ {
			witness.Plonky2PubInputs[i] = goldilocks.GetGoldilocksVariable(t_i.plonky2PubInputs[i])
		}
		for i := 0; i < nGnarkPubInputs; i++ {
			witness.GnarkPubInputs[i] = frontend.Variable(t_i.gnarkPubInputs[i])
		}

		w, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal("Error in witness: ", err, "\n test: ", t_i)
		}
		err = r1cs.IsSolved(w)
		if err != nil {
			t.Fatal("Circuit not solved: ", err, "\n test: ", t_i)
		}
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254))
	}
}
