package goldilocks

type GoldilocksExtension2Variable struct {
	A GoldilocksVariable
	B GoldilocksVariable
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
