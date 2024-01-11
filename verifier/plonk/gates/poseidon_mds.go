package gates

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	algebra "github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks/extension"
	poseidon "github.com/Electron-Labs/plonky2-groth16-verifier/poseidon/goldilocks"
	"github.com/consensys/gnark/frontend"
)

type PoseidonMdsGate struct {
	NumCoeffs int `json:"num_coeffs"`
}

var POSEIDON_MDS_CIRC []*big.Int = poseidon.POSEIDON_MDS_CIRC()
var POSEIDON_MDS_DIAG []*big.Int = poseidon.POSEIDON_MDS_DIAG()

func NewPoseidonMdsGate(id string) *PoseidonMdsGate {
	if !strings.HasPrefix(id, "PoseidonMdsGate") {
		panic(fmt.Sprintln("Invalid gate id: ", id))
	}

	return new(PoseidonMdsGate)
}

func (gate *PoseidonMdsGate) EvalUnfiltered(api frontend.API, rangeChecker frontend.Rangechecker, vars EvaluationVars) []goldilocks.GoldilocksExtension2Variable {
	constraints := make([]goldilocks.GoldilocksExtension2Variable, poseidon.SPONGE_WIDTH*2)

	inputs := make([][D][D]frontend.Variable, poseidon.SPONGE_WIDTH)
	for i := 0; i < poseidon.SPONGE_WIDTH; i++ {
		inputs[i] = GetLocalExtAlgebra(vars.LocalWires, gate.wiresInput(i))
	}
	computedOutputs := gate.mdsLayerAlgebraNoReduce(api, inputs)
	for i := 0; i < poseidon.SPONGE_WIDTH; i++ {
		out := GetLocalExtAlgebra(vars.LocalWires, gate.wiresOutput(i))
		// assuming computedOutputs[i] is always > out
		constraintNoReduce := algebra.SubNoReduce(api, computedOutputs[i], out)
		constraints[2*i] = goldilocks.NegExt(api, goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0][0], 82),
			B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[0][1], 82),
		})
		constraints[2*i+1] = goldilocks.NegExt(api, goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1][0], 82),
			B: goldilocks.Reduce(api, rangeChecker, constraintNoReduce[1][1], 82),
		})
	}

	return constraints
}

func (gate *PoseidonMdsGate) wiresInput(i int) [2]int {
	return [2]int{i * D, (i + 1) * D}
}

func (gate *PoseidonMdsGate) wiresOutput(i int) [2]int {
	return [2]int{(poseidon.SPONGE_WIDTH + i) * D, (poseidon.SPONGE_WIDTH + i + 1) * D}
}

// Same as `mds_row_shf` for an extension algebra of `F`.
func (gate *PoseidonMdsGate) mdsRowShfAlgebraNoReduce(api frontend.API,
	r int,
	v [][D][D]frontend.Variable,
) [D][D]frontend.Variable {
	if len(v) != poseidon.SPONGE_WIDTH {
		panic("mdsRowShfAlgebraNoReduce::Invalid length of `v`")
	}
	res := algebra.FromBase(goldilocks.BaseTo2ExtRaw(0))

	for i := 0; i < poseidon.SPONGE_WIDTH; i++ {
		coeff := goldilocks.BaseTo2ExtRaw(POSEIDON_MDS_CIRC[i])
		res = algebra.AddNoReduce(api, res, algebra.ScalarMulNoReduce(api, v[(i+r)%poseidon.SPONGE_WIDTH], coeff))
	}
	coeff := goldilocks.BaseTo2ExtRaw(POSEIDON_MDS_DIAG[r])
	res = algebra.AddNoReduce(api, res, algebra.ScalarMulNoReduce(api, v[r], coeff))

	return res
}

// Same as `mds_layer` for an extension algebra of `F`.
func (gate *PoseidonMdsGate) mdsLayerAlgebraNoReduce(
	api frontend.API,
	state [][D][D]frontend.Variable,
) [][D][D]frontend.Variable {
	if len(state) != poseidon.SPONGE_WIDTH {
		panic("mdsLayerAlgebraNoReduce::Invalid length of `state`")
	}
	resultNoReduce := make([][D][D]frontend.Variable, poseidon.SPONGE_WIDTH)
	for r := 0; r < poseidon.SPONGE_WIDTH; r++ {
		resultNoReduce[r] = gate.mdsRowShfAlgebraNoReduce(api, r, state)
	}
	return resultNoReduce
}
