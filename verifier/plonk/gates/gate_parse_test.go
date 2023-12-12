package gates

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	g := ParseGate("ArithmeticGate { num_ops: 20 }")
	airthmetic, ok := g.(*ArithmeticGate)
	assert.True(t, ok, "Type assertion failed")
	assert.Equal(t, 20, airthmetic.NumOps, "Wrong number of ops")

	g = ParseGate("ConstantGate { num_consts: 2 }")
	constant, ok := g.(*ConstantGate)
	assert.True(t, ok, "Type assertion failed")
	assert.Equal(t, 2, constant.NumConsts, "Wrong number of consts")

	g = ParseGate("PublicInputGate")
	_, ok = g.(*PublicInputGate)
	assert.True(t, ok, "Type assertion failed")

	g = ParseGate("PoseidonGate(PhantomData<plonky2_field::goldilocks_field::GoldilocksField>)<WIDTH=12>")
	_, ok = g.(*PoseidonGate)
	assert.True(t, ok, "Type assertion failed")
}
