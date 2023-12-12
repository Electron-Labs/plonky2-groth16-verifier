package fri

import (
	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/types"
	"github.com/consensys/gnark/frontend"
)

func FriPreprocessedPolys(common_data types.CommonData) []types.FriPolynomialInfo {
	return types.FromRange(types.CONSTANT_SIGMAS.Index, types.Range{
		Start: 0,
		End:   common_data.NumConstants + common_data.Config.NumRoutedWires,
	})
}

func FriWirePolys(common_data types.CommonData) []types.FriPolynomialInfo {
	return types.FromRange(types.WIRES.Index, types.Range{
		Start: 0,
		End:   common_data.Config.NumWires,
	})
}

func FriZsPartialProductsPolys(common_data types.CommonData) []types.FriPolynomialInfo {
	return types.FromRange(types.ZS_PARTIAL_PRODUCTS.Index, types.Range{
		Start: 0,
		End:   common_data.Config.NumChallenges * (1 + common_data.NumPartialProducts),
	})
}

func FriQuotientPolys(common_data types.CommonData) []types.FriPolynomialInfo {
	return types.FromRange(types.QUOTIENT.Index, types.Range{
		Start: 0,
		End:   common_data.Config.NumChallenges * common_data.QuotientDegreeFactor,
	})
}

func FriLookupPolys(common_data types.CommonData) []types.FriPolynomialInfo {
	return types.FromRange(types.ZS_PARTIAL_PRODUCTS.Index, types.Range{
		Start: common_data.Config.NumChallenges * (1 + common_data.NumPartialProducts),
		End:   common_data.Config.NumChallenges * (1 + common_data.NumPartialProducts + common_data.NumLookupPolys),
	})
}

func FriAllPolys(common_data types.CommonData) []types.FriPolynomialInfo {
	var all_polys []types.FriPolynomialInfo
	all_polys = append(all_polys, FriPreprocessedPolys(common_data)...)
	all_polys = append(all_polys, FriWirePolys(common_data)...)
	all_polys = append(all_polys, FriZsPartialProductsPolys(common_data)...)
	all_polys = append(all_polys, FriQuotientPolys(common_data)...)
	all_polys = append(all_polys, FriLookupPolys(common_data)...)
	return all_polys
}

func FriZsPolys(common_data types.CommonData) []types.FriPolynomialInfo {
	return types.FromRange(types.ZS_PARTIAL_PRODUCTS.Index, types.Range{
		Start: 0,
		End:   common_data.Config.NumChallenges,
	})
}

func FriNextBatchPolys(common_data types.CommonData) []types.FriPolynomialInfo {
	var all_polys []types.FriPolynomialInfo
	all_polys = append(all_polys, FriZsPolys(common_data)...)
	all_polys = append(all_polys, FriLookupPolys(common_data)...)
	return all_polys
}

func FriOracles(common_data types.CommonData) []types.FriOracleInfo {
	return []types.FriOracleInfo{
		{
			NumPolys: int(common_data.NumConstants + common_data.Config.NumRoutedWires),
			Blinding: types.CONSTANT_SIGMAS.Blinding,
		},
		{
			NumPolys: int(common_data.Config.NumWires),
			Blinding: types.WIRES.Blinding,
		},
		{
			NumPolys: int(common_data.Config.NumChallenges * (1 + common_data.NumPartialProducts + common_data.NumLookupPolys)),
			Blinding: types.ZS_PARTIAL_PRODUCTS.Blinding,
		},
		{
			NumPolys: int(common_data.Config.NumChallenges * common_data.QuotientDegreeFactor),
			Blinding: types.QUOTIENT.Blinding,
		},
	}
}

func GetFriInstance(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	common_data types.CommonData,
	zeta goldilocks.GoldilocksExtension2Variable,
) types.FriInstanceInfo {
	zeta_batch := types.FriBatchInfo{
		Point:       zeta,
		Polynomials: FriAllPolys(common_data),
	}

	g := goldilocks.PrimitveRootOfUnityExt(int(common_data.FriParams.DegreeBits))
	zeta_next := goldilocks.MulExt(api, rangeChecker, g, zeta)
	zeta_next_batch := types.FriBatchInfo{
		Point:       zeta_next,
		Polynomials: FriNextBatchPolys(common_data),
	}

	openings := []types.FriBatchInfo{zeta_batch, zeta_next_batch}
	return types.FriInstanceInfo{
		Oracles: FriOracles(common_data),
		Batches: openings,
	}
}

func GetFriOpenings(openings types.OpeningSetVariable) types.FriOpeningsVariable {
	values := openings.Constants
	values = append(values, openings.PlonkSigmas...)
	values = append(values, openings.Wires...)
	values = append(values, openings.PlonkZs...)
	values = append(values, openings.PartialProducts...)
	values = append(values, openings.QuotientPolys...)
	values = append(values, openings.LookupZs...)
	zetaBatch := types.FriOpeningBatchVariable{
		Values: values,
	}

	values = openings.PlonkZsNext
	values = append(values, openings.LookupZsNext...)
	zetaNextBatch := types.FriOpeningBatchVariable{
		Values: values,
	}
	friOpenings := types.FriOpeningsVariable{
		Batches: []types.FriOpeningBatchVariable{zetaBatch, zetaNextBatch},
	}
	return friOpenings
}
