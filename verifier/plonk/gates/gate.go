package gates

import (
	"fmt"
	"math"
	"strings"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier/types"
	"github.com/consensys/gnark/frontend"
)

const UNUSED_SELECTOR = math.MaxUint32

type Gate interface {
	EvalUnfiltered(api frontend.API, rangeChecker frontend.Rangechecker, vars EvaluationVars) []goldilocks.GoldilocksExtension2Variable
}

const D = goldilocks.D

func EvalFiltered(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	gate Gate,
	vars EvaluationVars,
	row int,
	selector_index int,
	group_range types.Range,
	num_selectors int,
	num_lookup_selectors int,
) []goldilocks.GoldilocksExtension2Variable {
	filter := compute_filter(
		api,
		rangeChecker,
		row,
		group_range,
		vars.LocalConstants[selector_index],
		num_selectors > 1,
	)
	vars.RemovePrefix(num_selectors)
	vars.RemovePrefix(num_lookup_selectors)
	constraints := gate.EvalUnfiltered(api, rangeChecker, vars)
	for i := range constraints {
		constraints[i] = goldilocks.MulExt(api, rangeChecker, constraints[i], filter)
	}
	return constraints
}

func ParseGate(gate_id string) Gate {
	if strings.Contains(gate_id, "ArithmeticGate") {

		return NewArithmeticGate(gate_id)

	} else if strings.Contains(gate_id, "ArithmeticExtensionGate") {

		return NewArithmeticExtensionGate(gate_id)

	} else if strings.Contains(gate_id, "BaseSumGate") {

		return NewBaseSumGate(gate_id)

	} else if strings.Contains(gate_id, "ConstantGate") {

		return NewConstantGate(gate_id)

	} else if strings.Contains(gate_id, "CosetInterpolationGate") {

		return NewCosetInterpolationGate(gate_id)

	} else if strings.Contains(gate_id, "ExponentiationGate") {

		return NewExponentiationGate(gate_id)

	} else if strings.Contains(gate_id, "LookupGate") {

		return NewLookupGate(gate_id)

	} else if strings.Contains(gate_id, "LookupTableGate") {

		return NewLookupTableGate(gate_id)

	} else if strings.Contains(gate_id, "MulExtensionGate") {

		return NewMulExtensionGate(gate_id)

	} else if strings.Contains(gate_id, "NoopGate") {

		return NewNoopGate(gate_id)

	} else if strings.Contains(gate_id, "PoseidonGate") {

		return NewPoseidonGate(gate_id)

	} else if strings.Contains(gate_id, "PoseidonMdsGate") {

		return NewPoseidonMdsGate(gate_id)

	} else if strings.Contains(gate_id, "PublicInputGate") {

		return NewPublicInputGate(gate_id)

	} else if strings.Contains(gate_id, "RandomAccessGate") {

		return NewRandomAccessGate(gate_id)

	} else if strings.Contains(gate_id, "ReducingGate") {

		return NewReducingGate(gate_id)

	} else if strings.Contains(gate_id, "ReducingExtensionGate") {

		return NewReducingExtensionGate(gate_id)

	} else if strings.Contains(gate_id, "ComparisonGate") {

		return NewU32ComparisonGate(gate_id)

	} else {
		panic(fmt.Sprintln("Unsupported gate:", gate_id))
	}
}

func compute_filter(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	row int,
	group_range types.Range,
	s goldilocks.GoldilocksExtension2Variable,
	many_selector bool,
) goldilocks.GoldilocksExtension2Variable {
	res := goldilocks.GetGoldilocksExtensionVariable([]uint64{1, 0})
	for i := group_range.Start; i < group_range.End; i++ {
		if i == uint64(row) {
			continue
		}
		t := goldilocks.GetGoldilocksExtensionVariable([]uint64{i, 0})
		t = goldilocks.SubExt(api, rangeChecker, t, s)
		res = goldilocks.MulExt(api, rangeChecker, res, t)
	}
	if many_selector {
		t := goldilocks.GetGoldilocksExtensionVariable([]uint64{UNUSED_SELECTOR, 0})
		t = goldilocks.SubExt(api, rangeChecker, t, s)
		res = goldilocks.MulExt(api, rangeChecker, res, t)
	}
	return res
}

func EvaluateGateConstraints(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	common_data types.CommonData,
	vars EvaluationVars,
) []goldilocks.GoldilocksExtension2Variable {
	constraints := make([]goldilocks.GoldilocksExtension2Variable, common_data.NumGateConstraints)
	for i := range constraints {
		constraints[i] = goldilocks.GetGoldilocksExtensionVariable([]uint64{0, 0})
	}
	for i, gate_s := range common_data.Gates {
		selector_index := common_data.SelectorsInfo.SelectorIndices[i]
		gate := ParseGate(gate_s)
		gate_constraints := EvalFiltered(
			api,
			rangeChecker,
			gate,
			vars,
			i,
			int(selector_index),
			common_data.SelectorsInfo.Groups[selector_index],
			common_data.SelectorsInfo.NumSelectors(),
			int(common_data.NumLookupSelectors),
		)
		for j, c := range gate_constraints {
			constraints[j] = goldilocks.AddExt(api, rangeChecker, constraints[j], c)
		}
	}
	return constraints
}
