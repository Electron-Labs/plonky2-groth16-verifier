package plonk

import (
	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/plonk/gates"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/types"
	"github.com/consensys/gnark/frontend"
)

func EvalVanishingPoly(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	common_data types.CommonData,
	x goldilocks.GoldilocksExtension2Variable,
	x_pow_deg goldilocks.GoldilocksExtension2Variable,
	vars gates.EvaluationVars,
	local_zs []goldilocks.GoldilocksExtension2Variable,
	next_zs []goldilocks.GoldilocksExtension2Variable,
	local_lookup_zs []goldilocks.GoldilocksExtension2Variable,
	next_lookup_zs []goldilocks.GoldilocksExtension2Variable,
	partial_products []goldilocks.GoldilocksExtension2Variable,
	s_sigmas []goldilocks.GoldilocksExtension2Variable,
	betas []goldilocks.GoldilocksVariable,
	gammas []goldilocks.GoldilocksVariable,
	alphas []goldilocks.GoldilocksVariable,
	deltas []goldilocks.GoldilocksVariable,
) []goldilocks.GoldilocksExtension2Variable {
	has_lookup := common_data.NumLookupPolys != 0
	max_degree := int(common_data.QuotientDegreeFactor)
	num_prods := int(common_data.NumPartialProducts)
	xVar := goldilocks.GetVariableArray(x)

	constraint_terms := gates.EvaluateGateConstraints(api, rangeChecker, common_data, vars)
	// lookup_selectors := vars.LocalConstants[common_data.SelectorsInfo.NumSelectors() : common_data.SelectorsInfo.NumSelectors()+int(common_data.NumLookupSelectors)]

	var vanishing_z_1_terms []goldilocks.GoldilocksExtension2Variable

	var vanishing_all_lookup_terms []goldilocks.GoldilocksExtension2Variable

	var vanishing_partial_products_terms []goldilocks.GoldilocksExtension2Variable

	l_0_x := EvalL0(api, rangeChecker, int(common_data.FriParams.DegreeBits), x, x_pow_deg)

	for i := 0; i < int(common_data.Config.NumChallenges); i++ {
		z_x := local_zs[i]
		z_gx := next_zs[i]
		vz1t := goldilocks.MulExtNoReduce(api,
			goldilocks.GetVariableArray(l_0_x),
			goldilocks.SubExtNoReduce(api,
				goldilocks.GetVariableArray(z_x),
				[2]frontend.Variable{1, 0},
			),
		)
		vanishing_z_1_terms = append(vanishing_z_1_terms, goldilocks.GoldilocksExtension2Variable{
			A: goldilocks.Reduce(api, rangeChecker, vz1t[0], 132),
			B: goldilocks.Reduce(api, rangeChecker, vz1t[1], 130),
		})

		if has_lookup {
			panic("todo")
		}

		var numerator_values []goldilocks.GoldilocksExtension2Variable
		var denominator_values []goldilocks.GoldilocksExtension2Variable
		for j := 0; j < int(common_data.Config.NumRoutedWires); j++ {
			wire_value := vars.LocalWires[j]
			wire_value_gamma := goldilocks.AddExtNoReduce(api,
				goldilocks.GetVariableArray(wire_value),
				[2]frontend.Variable{gammas[i].Limb, 0},
			)

			k_i := goldilocks.GetGoldilocksVariable(common_data.KIs[j])
			s_id := goldilocks.ScalarMulNoReduce(api,
				k_i.Limb,
				xVar,
			)
			t := goldilocks.AddExtNoReduce(api,
				wire_value_gamma,
				goldilocks.ScalarMulNoReduce(api,
					betas[i].Limb,
					s_id,
				),
			)
			numerator_values = append(numerator_values, goldilocks.GoldilocksExtension2Variable{
				A: goldilocks.Reduce(api, rangeChecker, t[0], 192),
				B: goldilocks.Reduce(api, rangeChecker, t[1], 192),
			})

			s_sigma := s_sigmas[j]
			t = goldilocks.AddExtNoReduce(api,
				wire_value_gamma,
				goldilocks.ScalarMulNoReduce(api,
					betas[i].Limb,
					goldilocks.GetVariableArray(s_sigma),
				),
			)
			denominator_values = append(denominator_values, goldilocks.GoldilocksExtension2Variable{
				A: goldilocks.Reduce(api, rangeChecker, t[0], 128),
				B: goldilocks.Reduce(api, rangeChecker, t[1], 128),
			})
		}

		current_partial_products := partial_products[i*num_prods : (i+1)*num_prods]

		partial_product_checks := check_partial_products(
			api,
			rangeChecker,
			numerator_values,
			denominator_values,
			current_partial_products,
			z_x,
			z_gx,
			max_degree,
		)
		vanishing_partial_products_terms = append(vanishing_partial_products_terms, partial_product_checks...)
	}

	var vanishing_terms []goldilocks.GoldilocksExtension2Variable
	vanishing_terms = append(vanishing_terms, vanishing_z_1_terms...)
	vanishing_terms = append(vanishing_terms, vanishing_partial_products_terms...)
	vanishing_terms = append(vanishing_terms, vanishing_all_lookup_terms...)
	vanishing_terms = append(vanishing_terms, constraint_terms...)

	alphas_ext := make([]goldilocks.GoldilocksExtension2Variable, len(alphas))
	for i, v := range alphas {
		alphas_ext[i].A = v
		alphas_ext[i].B.Limb = 0
	}
	return gates.ReduceWithPowersMulti(api, rangeChecker, vanishing_terms, alphas_ext)
}

func check_partial_products(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	numerators []goldilocks.GoldilocksExtension2Variable,
	denominators []goldilocks.GoldilocksExtension2Variable,
	partials []goldilocks.GoldilocksExtension2Variable,
	z_x goldilocks.GoldilocksExtension2Variable,
	z_gx goldilocks.GoldilocksExtension2Variable,
	max_degree int,
) []goldilocks.GoldilocksExtension2Variable {
	var checks []goldilocks.GoldilocksExtension2Variable

	var product_accs []goldilocks.GoldilocksExtension2Variable
	product_accs = append(product_accs, z_x)
	product_accs = append(product_accs, partials...)
	product_accs = append(product_accs, z_gx)

	chunk_size := max_degree
	num_chunks := (len(numerators)-1)/chunk_size + 1
	for i := 0; i < num_chunks; i++ {
		nume_chunk := numerators[i*chunk_size : min((i+1)*chunk_size, len(numerators))]
		deno_chunk := denominators[i*chunk_size : min((i+1)*chunk_size, len(denominators))]

		prev_acc := product_accs[i]
		next_acc := product_accs[i+1]

		num_chunk_product := nume_chunk[0]
		for i := 1; i < len(nume_chunk); i++ {
			num_chunk_product = goldilocks.MulExt(api, rangeChecker, num_chunk_product, nume_chunk[i])
		}

		den_chunk_product := deno_chunk[0]
		for i := 1; i < len(deno_chunk); i++ {
			den_chunk_product = goldilocks.MulExt(api, rangeChecker, den_chunk_product, deno_chunk[i])
		}

		term1 := goldilocks.MulExt(api, rangeChecker, num_chunk_product, prev_acc)
		term2 := goldilocks.MulExt(api, rangeChecker, den_chunk_product, next_acc)

		final := goldilocks.SubExt(api, rangeChecker, term1, term2)

		checks = append(checks, final)
	}

	return checks

}
