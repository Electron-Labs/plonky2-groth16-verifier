package fri

import (
	"math"
	"math/bits"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/hash"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/plonk"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/types"
	"github.com/consensys/gnark/frontend"
)

func FriVerifyProofOfWork(
	rangeChecker frontend.Rangechecker,
	fri_pow_response goldilocks.GoldilocksVariable,
	config types.FriConfig,
) {
	// Use rangeChecker.Check() or api.ToBits()?
	rangeChecker.Check(fri_pow_response.Limb, int(64-config.ProofOfWorkBits))
}

func FriVerifyInitialProof(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	x_index_bits []frontend.Variable,
	proof types.FriInitialTreeProofVariable,
	initial_merkle_caps []types.MerkleCapVariable,
) {
	for i := range proof.EvalsProofs {
		hash.VerifyMerkleProofToCap(
			api,
			rangeChecker,
			proof.EvalsProofs[i].X,
			x_index_bits,
			initial_merkle_caps[i],
			proof.EvalsProofs[i].Y,
		)
	}
}

func FriCombineInitial(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	instance types.FriInstanceInfo,
	proof types.FriInitialTreeProofVariable,
	alpha goldilocks.GoldilocksExtension2Variable,
	subgroup_x goldilocks.GoldilocksVariable,
	precomputed_reduced_evals []goldilocks.GoldilocksExtension2Variable,
	params types.FriParams,
) goldilocks.GoldilocksExtension2Variable {
	var subgroup_x_ext goldilocks.GoldilocksExtension2Variable
	subgroup_x_ext.A.Limb = subgroup_x.Limb
	subgroup_x_ext.B.Limb = 0
	sum := goldilocks.GetGoldilocksExtensionVariable([]uint64{0, 0})
	for i, batch := range instance.Batches {
		reduced_openings := precomputed_reduced_evals[i]
		point := batch.Point
		polynomials := batch.Polynomials
		var evals []goldilocks.GoldilocksExtension2Variable
		for _, p := range polynomials {
			poly_blinding := instance.Oracles[p.OracleIndex].Blinding
			salted := params.Hiding && poly_blinding
			evals = append(evals, goldilocks.GoldilocksExtension2Variable{
				A: proof.UnsaltedEval(p.OracleIndex, p.PolynomialIndex, salted),
				B: goldilocks.GetGoldilocksVariable(0),
			})
		}
		reduced_evals := plonk.ReduceWithPowers(api, rangeChecker, evals, alpha)
		numerator := goldilocks.SubExt(api, rangeChecker, reduced_evals, reduced_openings)
		denominator := goldilocks.SubExt(api, rangeChecker, subgroup_x_ext, point)
		if i == 0 {
			sum = goldilocks.DivExt(api, rangeChecker, numerator, denominator)
		} else {
			// Shift func
			count := frontend.Variable(len(evals))
			count_bits := api.ToBinary(count, 64)
			sum = goldilocks.MulExt(api, rangeChecker, goldilocks.ExpExt(api, rangeChecker, alpha, count_bits), sum)

			sum = goldilocks.AddExt(api, rangeChecker, sum, goldilocks.DivExt(api, rangeChecker, numerator, denominator))
		}
	}
	return sum
}

func BarycentricWeights(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	point_x []goldilocks.GoldilocksExtension2Variable,
) []goldilocks.GoldilocksExtension2Variable {
	barycentric_weights := make([]goldilocks.GoldilocksExtension2Variable, len(point_x))
	for i := 0; i < len(point_x); i++ {
		barycentric_weights[i] = goldilocks.GetGoldilocksExtensionVariable([]uint64{1, 0})
		for j := 0; j < len(point_x); j++ {
			if i != j {
				no_reduce := api.Mul(
					barycentric_weights[i].A.Limb,
					api.Add(
						api.Sub(point_x[i].A.Limb, point_x[j].A.Limb),
						goldilocks.MODULUS,
					),
				)
				barycentric_weights[i].A = goldilocks.Reduce(api, rangeChecker, no_reduce, 129) // 129 max number of bits for the above operation in goldilocks field
			}
		}
		barycentric_weights[i].A = goldilocks.Inv(api, rangeChecker, barycentric_weights[i].A)
	}
	return barycentric_weights
}

func Interpolate(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	point_x []goldilocks.GoldilocksExtension2Variable,
	point_y []goldilocks.GoldilocksExtension2Variable,
	x goldilocks.GoldilocksExtension2Variable,
	barycentric_weights []goldilocks.GoldilocksExtension2Variable,
) goldilocks.GoldilocksExtension2Variable {
	l_x := goldilocks.GetGoldilocksExtensionVariable([]uint64{1, 0})
	for _, pt_x := range point_x {
		tmp_x := api.Add(api.Sub(x.A.Limb, pt_x.A.Limb), goldilocks.MODULUS)
		no_reduce := goldilocks.MulExtNoReduce(
			api,
			goldilocks.GetVariableArray(l_x),
			[2]frontend.Variable{tmp_x, x.B.Limb},
		)
		l_x = goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, no_reduce[0], 132),
			B: goldilocks.Reduce(api, rangeChecker, no_reduce[1], 130),
		}
	}

	sum := goldilocks.GetGoldilocksExtensionVariable([]uint64{0, 0})
	for i, pt_x := range point_x {
		pt_y := point_y[i]
		w_i := barycentric_weights[i]

		sum = goldilocks.AddExt(
			api, rangeChecker,
			goldilocks.MulExt(
				api, rangeChecker,
				goldilocks.DivExt(
					api, rangeChecker,
					w_i,
					goldilocks.SubExt(
						api, rangeChecker,
						x,
						pt_x,
					),
				),
				pt_y,
			),
			sum,
		)
	}

	interpolated_value := goldilocks.MulExt(api, rangeChecker, l_x, sum)

	return interpolated_value
}

func ComputeEvaluation(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	x goldilocks.GoldilocksVariable,
	x_index_within_coset_bits []frontend.Variable,
	arity_bits int,
	evals []goldilocks.GoldilocksExtension2Variable,
	beta goldilocks.GoldilocksExtension2Variable,
) goldilocks.GoldilocksExtension2Variable {
	arity := 1 << arity_bits
	g := goldilocks.PrimitveRootOfUnity(arity_bits)
	log_eval_size := int(math.Log2(float64(len(evals))))

	// reverse index bits in place
	permuted_evals := make([]goldilocks.GoldilocksExtension2Variable, len(evals))
	for i := uint64(0); i < uint64(len(evals)); i++ {
		new_i := bits.Reverse64(i) >> (64 - log_eval_size)
		permuted_evals[new_i] = evals[i]
	}
	evals = permuted_evals

	// reverse_bits
	rev_x_index_within_coset_bits := make([]frontend.Variable, arity_bits)
	for i := 0; i < arity_bits; i += 1 {
		rev_x_index_within_coset_bits[i] = x_index_within_coset_bits[arity_bits-1-i]
	}
	rev_x_index_within_coset := api.FromBinary(rev_x_index_within_coset_bits...)

	power_bits := api.ToBinary(api.Sub(arity, rev_x_index_within_coset), arity_bits+1)
	coset_start := goldilocks.Mul(api, rangeChecker, x, goldilocks.Exp(api, rangeChecker, g, power_bits))
	var points_x []goldilocks.GoldilocksExtension2Variable
	current := goldilocks.GetGoldilocksVariable(1)
	for i := range evals {
		pt := goldilocks.Mul(api, rangeChecker, coset_start, current)
		if i < len(evals)-1 {
			current = goldilocks.Mul(api, rangeChecker, current, g)
		}
		points_x = append(points_x, goldilocks.GoldilocksExtension2Variable{A: pt, B: goldilocks.GetGoldilocksVariable(0)})
	}
	barycentric_weights := BarycentricWeights(api, rangeChecker, points_x)
	return Interpolate(api, rangeChecker, points_x, evals, beta, barycentric_weights)
}

func FriVerifierQueryRound(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	instance types.FriInstanceInfo,
	challenges types.FriChallengesVariable,
	precomputed_reduced_evals []goldilocks.GoldilocksExtension2Variable,
	initial_merkle_caps []types.MerkleCapVariable,
	proof types.FriProofVariable,
	x_index frontend.Variable,
	n int,
	round_proof types.FriQueryRoundVariable,
	params types.FriParams,
) {
	x_index_bits := api.ToBinary(x_index, 64)
	FriVerifyInitialProof(api, rangeChecker, x_index_bits, round_proof.InitialTreeProof, initial_merkle_caps)

	log_n := int(math.Log2(float64(n)))
	// reverse_bits
	power_bits := make([]frontend.Variable, log_n)
	for i := 0; i < log_n; i += 1 {
		power_bits[i] = x_index_bits[log_n-1-i]
	}
	subgroup_x := goldilocks.Mul(
		api,
		rangeChecker,
		goldilocks.GetGoldilocksVariable(goldilocks.MULTIPLICATIVE_GROUP_GENERATOR),
		goldilocks.Exp(
			api,
			rangeChecker,
			goldilocks.PrimitveRootOfUnity(log_n),
			power_bits,
		),
	)
	old_eval := FriCombineInitial(
		api,
		rangeChecker,
		instance,
		round_proof.InitialTreeProof,
		challenges.FriAlpha,
		subgroup_x,
		precomputed_reduced_evals,
		params,
	)

	for i, arity_bits := range params.ReductionArityBits {
		evals := round_proof.Steps[i].Evals
		coset_index_bits := x_index_bits[arity_bits:]
		x_index_within_coset_bits := x_index_bits[:arity_bits]

		// consistency check
		eval_index := goldilocks.SelectGoldilocksExt2Recursive(api, x_index_within_coset_bits, evals)[0]
		api.AssertIsEqual(eval_index.A.Limb, old_eval.A.Limb)
		api.AssertIsEqual(eval_index.B.Limb, old_eval.B.Limb)

		old_eval = ComputeEvaluation(
			api,
			rangeChecker,
			subgroup_x,
			x_index_within_coset_bits,
			int(arity_bits),
			evals,
			challenges.FriBetas[i],
		)

		hash.VerifyMerkleProofToCap(
			api,
			rangeChecker,
			goldilocks.Flatten(evals),
			coset_index_bits,
			proof.CommitPhaseMerkleCap[i],
			round_proof.Steps[i].MerkleProof,
		)

		subgroup_x = goldilocks.ExpPow2(api, rangeChecker, subgroup_x, int(arity_bits))
		x_index_bits = coset_index_bits
	}

	final_eval := goldilocks.GetGoldilocksExtensionVariable([]uint64{0, 0})
	for i := len(proof.FinalPoly.Coeffs) - 1; i >= 0; i-- {
		c := proof.FinalPoly.Coeffs[i]
		if i == len(proof.FinalPoly.Coeffs)-1 {
			final_eval = c
		} else {
			mul := goldilocks.ScalarMulNoReduce(api, subgroup_x.Limb, goldilocks.GetVariableArray(final_eval))
			acc := goldilocks.AddExtNoReduce(api, goldilocks.GetVariableArray(c), mul)
			final_eval = goldilocks.GoldilocksExtension2Variable{
				A: goldilocks.Reduce(api, rangeChecker, acc[0], 128),
				B: goldilocks.Reduce(api, rangeChecker, acc[1], 128),
			}
		}
	}

	api.AssertIsEqual(final_eval.A.Limb, old_eval.A.Limb)
	api.AssertIsEqual(final_eval.B.Limb, old_eval.B.Limb)
}

func VerifyFriProof(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	instance types.FriInstanceInfo,
	openings types.FriOpeningsVariable,
	challenges types.FriChallengesVariable,
	initial_merkle_caps []types.MerkleCapVariable,
	proof types.FriProofVariable,
	params types.FriParams,
) {
	n := (1 << (params.DegreeBits + params.Config.RateBits))

	FriVerifyProofOfWork(rangeChecker, challenges.FriPowResponse, params.Config)

	var precomputed_reduced_evals []goldilocks.GoldilocksExtension2Variable
	for _, batch := range openings.Batches {
		precomputed_reduced_evals = append(precomputed_reduced_evals, plonk.ReduceWithPowers(api, rangeChecker, batch.Values, challenges.FriAlpha))
	}
	for i := range challenges.FriQueryIndices {
		FriVerifierQueryRound(
			api,
			rangeChecker,
			instance,
			challenges,
			precomputed_reduced_evals,
			initial_merkle_caps,
			proof,
			challenges.FriQueryIndices[i],
			n,
			proof.QueryRoundProofs[i],
			params,
		)
	}
}
