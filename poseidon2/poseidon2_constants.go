package poseidon2

import (
	"fmt"
	"math/big"
)

const WIDTH = 12
const ROUND_F_BEGIN = 4
const ROUND_F_END = 2 * ROUND_F_BEGIN
const ROUND_P = 22

func hexToBigInt(s string) (*big.Int, bool) {
	n := new(big.Int)
	out, ok := n.SetString(s, 16)
	return out, ok

}

func RC12(i int, j int) *big.Int {
	rci2 := [ROUND_F_END][WIDTH]string{
		{
			"13dcf33aba214f46",
			"30b3b654a1da6d83",
			"1fc634ada6159b56",
			"937459964dc03466",
			"edd2ef2ca7949924",
			"ede9affde0e22f68",
			"8515b9d6bac9282d",
			"6b5c07b4e9e900d8",
			"1ec66368838c8a08",
			"9042367d80d1fbab",
			"400283564a3c3799",
			"4a00be0466bca75e",
		},
		{
			"7913beee58e3817f",
			"f545e88532237d90",
			"22f8cb8736042005",
			"6f04990e247a2623",
			"fe22e87ba37c38cd",
			"d20e32c85ffe2815",
			"117227674048fe73",
			"4e9fb7ea98a6b145",
			"e0866c232b8af08b",
			"00bbc77916884964",
			"7031c0fb990d7116",
			"240a9e87cf35108f",
		},
		{
			"2e6363a5a12244b3",
			"5e1c3787d1b5011c",
			"4132660e2a196e8b",
			"3a013b648d3d4327",
			"f79839f49888ea43",
			"fe85658ebafe1439",
			"b6889825a14240bd",
			"578453605541382b",
			"4508cda8f6b63ce9",
			"9c3ef35848684c91",
			"0812bde23c87178c",
			"fe49638f7f722c14",
		},
		{
			"8e3f688ce885cbf5",
			"b8e110acf746a87d",
			"b4b2e8973a6dabef",
			"9e714c5da3d462ec",
			"6438f9033d3d0c15",
			"24312f7cf1a27199",
			"23f843bb47acbf71",
			"9183f11a34be9f01",
			"839062fbb9d45dbf",
			"24b56e7e6c2e43fa",
			"e1683da61c962a72",
			"a95c63971a19bfa7",
		},
		{
			"c68be7c94882a24d",
			"af996d5d5cdaedd9",
			"9717f025e7daf6a5",
			"6436679e6e7216f4",
			"8a223d99047af267",
			"bb512e35a133ba9a",
			"fbbf44097671aa03",
			"f04058ebf6811e61",
			"5cca84703fac7ffb",
			"9b55c7945de6469f",
			"8e05bf09808e934f",
			"2ea900de876307d7",
		},
		{
			"7748fff2b38dfb89",
			"6b99a676dd3b5d81",
			"ac4bb7c627cf7c13",
			"adb6ebe5e9e2f5ba",
			"2d33378cafa24ae3",
			"1e5b73807543f8c2",
			"09208814bfebb10f",
			"782e64b6bb5b93dd",
			"add5a48eac90b50f",
			"add4c54c736ea4b1",
			"d58dbb86ed817fd8",
			"6d5ed1a533f34ddd",
		},
		{
			"28686aa3e36b7cb9",
			"591abd3476689f36",
			"047d766678f13875",
			"a2a11112625f5b49",
			"21fd10a3f8304958",
			"f9b40711443b0280",
			"d2697eb8b2bde88e",
			"3493790b51731b3f",
			"11caf9dd73764023",
			"7acfb8f72878164e",
			"744ec4db23cefc26",
			"1e00e58f422c6340",
		},
		{
			"21dd28d906a62dda",
			"f32a46ab5f465b5f",
			"bfce13201f3f7e6b",
			"f30d2e7adb5304e2",
			"ecdf4ee4abad48e9",
			"f94e82182d395019",
			"4ee52e3744d887c5",
			"a1341c7cac0083b2",
			"2302fb26c30c834a",
			"aea3c587273bf7d3",
			"f798e24961823ec7",
			"962deba3e9a2cd94",
		},
	}

	out, ok := hexToBigInt(rci2[i][j])
	if !ok {
		panic(fmt.Sprintf("RC12 hexToBigInt %s", rci2[i][j]))
	}
	return out
}

func RC12_MID(i int) *big.Int {
	rc12Mid := [ROUND_P]string{
		"4adf842aa75d4316",
		"f8fbb871aa4ab4eb",
		"68e85b6eb2dd6aeb",
		"07a0b06b2d270380",
		"d94e0228bd282de4",
		"8bdd91d3250c5278",
		"209c68b88bba778f",
		"b5e18cdab77f3877",
		"b296a3e808da93fa",
		"8370ecbda11a327e",
		"3f9075283775dad8",
		"b78095bb23c6aa84",
		"3f36b9fe72ad4e5f",
		"69bc96780b10b553",
		"3f1d341f2eb7b881",
		"4e939e9815838818",
		"da366b3ae2a31604",
		"bc89db1e7287d509",
		"6102f411f9ef5659",
		"58725c5e7ac1f0ab",
		"0df5856c798883e7",
		"f7bb62a8da4c961b",
	}
	out, ok := hexToBigInt(rc12Mid[i])
	if !ok {
		panic(fmt.Sprintf("RC12_MID hexToBigInt %s", rc12Mid[i]))
	}
	return out
}

func MAT_DIAG12_M_1(i int) *big.Int {
	matDiag12M1 := [WIDTH]string{
		"c3b6c08e23ba9300",
		"d84b5de94a324fb6",
		"0d0c371c5b35b84f",
		"7964f570e7188037",
		"5daf18bbd996604b",
		"6743bc47b9595257",
		"5528b9362c59bb70",
		"ac45e25b7127b68b",
		"a2077d7dfbb606b5",
		"f3faac6faee378ae",
		"0c6388b51545e883",
		"d27dbb6944917b60",
	}
	out, ok := hexToBigInt(matDiag12M1[i])
	if !ok {
		panic(fmt.Sprintf("MAT_DIAG12_M_1 hexToBigInt %s", matDiag12M1[i]))
	}
	return out
}
