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

func MulNoReduce(
	api frontend.API,
	in1 [D][D]frontend.Variable,
	in2 [D][D]frontend.Variable,
) [D][D]frontend.Variable {

	zero := frontend.Variable(0)

	// initialize to 0
	res := [D][D]frontend.Variable{{zero, zero}, {zero, zero}}
	w := [D]frontend.Variable{goldilocks.W, zero}

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
		out[i] = goldilocks.SubExtNoReduce(api, out[i], in2[i])
	}
	return out
}
