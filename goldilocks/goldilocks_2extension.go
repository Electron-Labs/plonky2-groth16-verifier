package goldilocks

import (
	"github.com/consensys/gnark/frontend"
)

type GoldilocksExtension2Variable struct {
	A GoldilocksVariable
	B GoldilocksVariable
}

func (goldilocks_extension2 *GoldilocksExtension2Variable) RangeCheck(api frontend.API, rangeChecker frontend.Rangechecker) {
	RangeCheck(api, rangeChecker, goldilocks_extension2.A.Limb)
	RangeCheck(api, rangeChecker, goldilocks_extension2.B.Limb)
}

func GetGoldilocksExtensionVariable(vals []uint64) GoldilocksExtension2Variable {
	e0 := GetGoldilocksVariable(vals[0])
	e1 := GetGoldilocksVariable(vals[1])
	e := GoldilocksExtension2Variable{
		A: e0,
		B: e1,
	}

	return e
}

func GetGoldilocksExtensionVariableArr(vals [][]uint64) []GoldilocksExtension2Variable {
	var extensionVariable []GoldilocksExtension2Variable
	for _, elm := range vals {
		extensionVariable = append(extensionVariable, GetGoldilocksExtensionVariable(elm))
	}

	return extensionVariable
}
