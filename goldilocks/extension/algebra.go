package algebra

import (
	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/consensys/gnark/frontend"
)

const D = 2

type GoldilocksExtension2Algebra2Variable struct {
	A goldilocks.GoldilocksExtension2Variable
	B goldilocks.GoldilocksExtension2Variable
}

// [[136, 133], [133, 130]] bits given each variable in in1 and in2 is of 64bits
func MulNoReduce(
	api frontend.API,
	in1 [D][D]frontend.Variable,
	in2 [D][D]frontend.Variable,
) [D][D]frontend.Variable {

	// initialize to 0
	res := ZERO()
	w := goldilocks.BaseTo2ExtRaw(goldilocks.W)

	for i := 0; i < D; i++ {
		for j := 0; j < D; j++ {
			if i+j < D {
				res[(i+j)%D] = goldilocks.AddExtNoReduce(api, res[(i+j)%D], goldilocks.MulExtNoReduce(api, in1[i], in2[j]))
			} else {
				res[(i+j)%D] = goldilocks.AddExtNoReduce(api, res[(i+j)%D],
					goldilocks.MulExtNoReduce(api, goldilocks.MulExtNoReduce(api, w, in1[i]), in2[j]))
			}
		}
	}

	return res
}

func ScalarMulNoReduce(api frontend.API, in [D][D]frontend.Variable, scalar [D]frontend.Variable) [D][D]frontend.Variable {
	out := [D][D]frontend.Variable{{in[0][0], in[0][1]}, {in[1][0], in[1][1]}}
	for i := 0; i < len(out); i++ {
		out[i] = goldilocks.MulExtNoReduce(api, out[i], scalar)
	}
	return out
}

func AddNoReduce(api frontend.API, in1 [D][D]frontend.Variable, in2 [D][D]frontend.Variable) [D][D]frontend.Variable {
	out := [D][D]frontend.Variable{{in1[0][0], in1[0][1]}, {in1[1][0], in1[1][1]}}
	for i := 0; i < D; i++ {
		out[i] = goldilocks.AddExtNoReduce(api, out[i], in2[i])
	}
	return out
}

func SubNoReduce(api frontend.API, in1 [D][D]frontend.Variable, in2 [D][D]frontend.Variable) [D][D]frontend.Variable {
	out := [D][D]frontend.Variable{{in1[0][0], in1[0][1]}, {in1[1][0], in1[1][1]}}
	for i := 0; i < D; i++ {
		for j := 0; j < D; j++ {
			out[i][j] = api.Add(api.Sub(in1[i][j], in2[i][j]), goldilocks.MODULUS)
		}
	}
	return out
}

func Sub(api frontend.API, rangeChecker frontend.Rangechecker, in1 [D][D]frontend.Variable, in2 [D][D]frontend.Variable) [D][D]frontend.Variable {
	out := [D][D]frontend.Variable{{in1[0][0], in1[0][1]}, {in1[1][0], in1[1][1]}}
	for i := 0; i < D; i++ {
		for j := 0; j < D; j++ {
			out[i][j] = goldilocks.Sub(api, rangeChecker, goldilocks.GetGoldilocks(in1[i][j]), goldilocks.GetGoldilocks(in2[i][j])).Limb
		}
	}
	return out
}

func GetVariableArray(in [D]goldilocks.GoldilocksExtension2Variable) [D][D]frontend.Variable {
	out := [D][D]frontend.Variable{}
	for i, elm := range in {
		out[i] = goldilocks.GetVariableArray(elm)
	}
	return out
}

func FromBase(x [D]frontend.Variable) [D][D]frontend.Variable {
	return [D][D]frontend.Variable{
		{x[0], x[1]},
		{0, 0},
	}
}

func ZERO() [D][D]frontend.Variable {
	return [D][D]frontend.Variable{goldilocks.ZERO(), goldilocks.ZERO()}
}
