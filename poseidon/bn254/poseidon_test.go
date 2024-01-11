package poseidon

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

type TestPermuteCircuit struct {
	Inputs  []frontend.Variable
	Outputs []frontend.Variable
}

func (circuit *TestPermuteCircuit) Define(api frontend.API) error {
	poseidon := &PoseidonBn254{}
	outputs := poseidon.Permute(api, circuit.Inputs)
	for i := 0; i < WIDTH; i++ {
		api.AssertIsEqual(outputs[i], circuit.Outputs[i])
	}
	return nil
}

func TestPermute(t *testing.T) {
	assert := test.NewAssert(t)

	type testData struct {
		inputs  []frontend.Variable
		outputs []frontend.Variable
	}

	maxValue := frontend.Variable("21888242871839275222246405745257275088548364400416034343698204186575808495616")

	tests := []testData{
		{
			inputs: []frontend.Variable{0, 0, 0, 0},
			outputs: []frontend.Variable{
				"5317387130258456662214331362918410991734007599705406860481038345552731150762",
				"17768273200467269691696191901389126520069745877826494955630904743826040320364",
				"19413739268543925182080121099097652227979760828059217876810647045303340666757",
				"3717738800218482999400886888123026296874264026760636028937972004600663725187",
			},
		},
		{
			inputs: []frontend.Variable{0, 1, 2, 3},
			outputs: []frontend.Variable{
				"6542985608222806190361240322586112750744169038454362455181422643027100751666",
				"3478427836468552423396868478117894008061261013954248157992395910462939736589",
				"1904980799580062506738911865015687096398867595589699208837816975692422464009",
				"11971464497515232077059236682405357499403220967704831154657374522418385384151",
			},
		},
		{
			inputs: []frontend.Variable{maxValue, maxValue, maxValue, maxValue},
			outputs: []frontend.Variable{
				"13055670547682322550638362580666986963569035646873545133474324633020685301274",
				"19087936485076376314486368416882351797015004625427655501762827988254486144933",
				"10391468779200270580383536396630001155994223659670674913170907401637624483385",
				"17202557688472898583549180366140168198092766974201433936205272956998081177816",
			},
		},
		{
			inputs: []frontend.Variable{
				"6542985608222806190361240322586112750744169038454362455181422643027100751666",
				"3478427836468552423396868478117894008061261013954248157992395910462939736589",
				"1904980799580062506738911865015687096398867595589699208837816975692422464009",
				"11971464497515232077059236682405357499403220967704831154657374522418385384151",
			},
			outputs: []frontend.Variable{
				"21792249080447013894140672594027696524030291802493510986509431008224624594361",
				"3536096706123550619294332177231935214243656967137545251021848527424156573335",
				"14869351042206255711434675256184369368509719143073814271302931417334356905217",
				"5027523131326906886284185656868809493297314443444919363729302983434650240523",
			},
		},
	}

	var circuit TestPermuteCircuit
	circuit.Inputs = make([]frontend.Variable, WIDTH)
	circuit.Outputs = make([]frontend.Variable, WIDTH)
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal("Error in compiling circuit: ", err)
	}

	for _, t_i := range tests {
		var witness TestPermuteCircuit
		witness.Inputs = make([]frontend.Variable, WIDTH)
		witness.Outputs = make([]frontend.Variable, WIDTH)
		for i := 0; i < WIDTH; i++ {
			witness.Inputs[i] = t_i.inputs[i]
			witness.Outputs[i] = t_i.outputs[i]
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
