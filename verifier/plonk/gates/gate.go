package gates

import (
	"fmt"
	"math"
	"strings"

	"github.com/Electron-Labs/plonky2-groth16-verifier/goldilocks"
	"github.com/Electron-Labs/plonky2-groth16-verifier/verifier"
	"github.com/consensys/gnark/frontend"
)

const UNUSED_SELECTOR = math.MaxUint32

type Gate interface {
	EvalUnfiltered(api frontend.API, rangeChecker frontend.Rangechecker, vars EvaluationVars) []goldilocks.GoldilocksExtension2Variable
}

func EvalFiltered(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	gate Gate,
	vars EvaluationVars,
	row int,
	selector_index int,
	group_range verifier.Range,
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
		panic("todo")
	} else if strings.Contains(gate_id, "ArithmeticExtensionGate") {
		panic("todo")
	} else if strings.Contains(gate_id, "BaseSumGate") {
		panic("todo")
	} else if strings.Contains(gate_id, "ConstantGate") {
		panic("todo")
	} else if strings.Contains(gate_id, "CosetInterpolationGate") {
		panic("todo")
	} else if strings.Contains(gate_id, "ExponentiationGate") {
		panic("todo")
	} else if strings.Contains(gate_id, "LookupGate") {
		panic("todo")
	} else if strings.Contains(gate_id, "LookupTableGate") {
		panic("todo")
	} else if strings.Contains(gate_id, "MulExtensionGate") {
		panic("todo")
	} else if strings.Contains(gate_id, "NoopGate") {
		panic("todo")
	} else if strings.Contains(gate_id, "PoseidonGate") {
		panic("todo")
	} else if strings.Contains(gate_id, "PoseidonMdsGate") {
		panic("todo")
	} else if strings.Contains(gate_id, "PublicInputGate") {
		panic("todo")
	} else if strings.Contains(gate_id, "RandomAccessGate") {
		panic("todo")
	} else if strings.Contains(gate_id, "ReducingGate") {
		panic("todo")
	} else if strings.Contains(gate_id, "ReducingExtensionGate") {
		panic("todo")
	} else {
		panic(fmt.Sprintln("Unsupported gate:", gate_id))
	}
}

func compute_filter(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	row int,
	group_range verifier.Range,
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
