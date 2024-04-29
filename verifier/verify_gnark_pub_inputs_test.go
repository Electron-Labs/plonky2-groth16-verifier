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
	nPisBreakdown    []uint64
}

func (circuit *VerifyGnarkPubInputsCircuit) Define(api frontend.API) error {
	VerifyGnarkPubInputs(api, circuit.Plonky2PubInputs, circuit.GnarkPubInputs, circuit.nPisBreakdown)
	return nil
}

func TestVerifyGnarkPubInputs(t *testing.T) {
	assert := test.NewAssert(t)

	type testData struct {
		plonky2PubInputs []uint64
		gnarkPubInputs   []string
		nPisBreakdown    []uint64
	}

	// python code to genetate test data: verifier/generatePublicInputs.py
	tests := []testData{
		{
			plonky2PubInputs: []uint64{3036297269, 3729460488, 1373751520, 2373291176, 1947646873, 3909450913, 1206480117, 336951175},
			gnarkPubInputs:   []string{"13393011274282095879594315630327045542", "186640198415561390510363651726742910458"},
			nPisBreakdown:    []uint64{1},
		},
		{
			plonky2PubInputs: []uint64{3600998387, 2997660450, 1713356043, 722158858, 1308330741, 2877788538, 35726163, 397866934, 1943773115, 2866451789, 3325046695, 3419030796, 44905451, 4201978963, 2355139258, 783315777, 820860415, 277910878, 2612492729, 3387857140, 121429275, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2155275863, 1525163729, 973890640, 3482415076, 3312296374, 575917403, 437610040, 461400510, 2147539116, 3063169681, 1341325047, 3017781880, 3547023231, 2124982907, 195238558, 789872470, 869307875, 662387920, 2436582879, 511650052, 525614038, 2873342065, 1295734685, 14504409, 30, 0, 0, 0, 0, 0, 0, 0, 781907759, 1020975199, 3905557141, 722854541, 88172236, 2255874416, 122495187, 206766913, 2433190412, 196846761, 2565462463, 2476610315, 1598880973, 3218075894, 3986813797, 56911651, 433382281, 551267344, 3179757710, 1668752944, 2449957687, 319381376, 2929731155, 676226171, 3159146359, 1231861764, 3095122455, 2818228891, 3002401293, 3245940475, 765945174, 472924986, 1644041072, 1756246866, 1462049704, 1426353389, 3565164673, 1385929108, 2423681636, 297310779, 4066350176, 1160315853, 3960217878, 805413657, 680350304, 3086344405, 3468894394, 189048619, 4222245300, 421959817, 1534788381, 595118239, 2538086539, 3008911656, 1992465601, 211496150, 2966231507, 1024316116, 4254254397, 1348075668, 2800175281, 1577893795, 2914968710, 782496291, 1835951478, 7749743, 0, 0, 0, 0, 0, 0, 1869442661, 7299886, 0, 0, 0, 0, 0, 0, 109, 0, 0, 0, 0, 0, 0, 0, 775237685, 12336, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 858863409, 3618614, 0, 0, 0, 0, 0, 0, 3224115, 0, 0, 0, 0, 0, 0, 0, 299336978, 4242783158, 3727645094, 2643560312, 3005422001, 555936989, 1579455450, 150052041, 4123267616, 845829797, 672013665, 3371205885, 2831291400, 3998244193, 2877497569, 2958542, 2652275876, 3860436729, 2505623144, 1824622508, 996194942, 1648611647, 1806689128, 302047131, 2696291954, 218329406, 4063181670, 1910398256, 943480519, 267401397, 4111471244, 140112677},
			gnarkPubInputs:   []string{"68446181853170600214572038089570650348", "283580189736436555266521025303754101428"},
			nPisBreakdown:    []uint64{6, 4, 1, 1, 5, 12},
		},
	}

	for i, t_i := range tests {
		nPlonky2PubInputs := len(tests[i].plonky2PubInputs)
		nGnarkPubInputs := len(tests[i].gnarkPubInputs)

		var circuit VerifyGnarkPubInputsCircuit
		circuit.Plonky2PubInputs = make([]goldilocks.GoldilocksVariable, nPlonky2PubInputs)
		circuit.GnarkPubInputs = make([]frontend.Variable, nGnarkPubInputs)
		circuit.nPisBreakdown = t_i.nPisBreakdown
		r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			t.Fatal("Error in compiling circuit: ", err)
		}

		var witness VerifyGnarkPubInputsCircuit
		witness.Plonky2PubInputs = make([]goldilocks.GoldilocksVariable, nPlonky2PubInputs)
		witness.GnarkPubInputs = make([]frontend.Variable, nGnarkPubInputs)
		witness.nPisBreakdown = t_i.nPisBreakdown
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
