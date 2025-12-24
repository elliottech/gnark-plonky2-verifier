package poseidon2

import (
	"github.com/consensys/gnark/frontend"
	gl "github.com/elliottech/gnark-plonky2-verifier/goldilocks"
)

const ROUNDS_F_HALF = 4
const ROUNDS_F = 8
const ROUNDS_P = 22
const WIDTH = 12
const RATE = 8
const OUT = 4

type GoldilocksState = [WIDTH]gl.Variable
type GoldilocksStateExtension = [WIDTH]gl.QuadraticExtensionVariable
type GoldilocksHashOut = [OUT]gl.Variable

type GoldilocksChip struct {
	api frontend.API `gnark:"-"`
	gl  *gl.Chip     `gnark:"-"`
}

func NewGoldilocksChip(api frontend.API) *GoldilocksChip {
	return &GoldilocksChip{api: api, gl: gl.New(api)}
}

func (c *GoldilocksChip) ExternalLinearLayerExtension(state GoldilocksStateExtension) GoldilocksStateExtension {
	for i := 0; i < 3; i++ {
		state4 := [4]gl.QuadraticExtensionVariable{state[4*i], state[4*i+1], state[4*i+2], state[4*i+3]}
		result4 := c.ApplyMat4MutExtension(state4)
		state[4*i] = result4[0]
		state[4*i+1] = result4[1]
		state[4*i+2] = result4[2]
		state[4*i+3] = result4[3]
	}

	var sums [4]gl.QuadraticExtensionVariable
	sums[0] = c.gl.AddExtension(c.gl.AddExtension(state[0], state[4]), state[8])
	sums[1] = c.gl.AddExtension(c.gl.AddExtension(state[1], state[5]), state[9])
	sums[2] = c.gl.AddExtension(c.gl.AddExtension(state[2], state[6]), state[10])
	sums[3] = c.gl.AddExtension(c.gl.AddExtension(state[3], state[7]), state[11])

	for i := 0; i < WIDTH; i++ {
		state[i] = c.gl.AddExtension(state[i], sums[i%4])
	}

	return state
}

func (c *GoldilocksChip) ApplyMat4MutExtension(x [4]gl.QuadraticExtensionVariable) [4]gl.QuadraticExtensionVariable {
	var result [4]gl.QuadraticExtensionVariable

	t01 := c.gl.AddExtension(x[0], x[1])
	t23 := c.gl.AddExtension(x[2], x[3])
	t0123 := c.gl.AddExtension(t01, t23)
	t01123 := c.gl.AddExtension(t0123, x[1])
	t01233 := c.gl.AddExtension(t0123, x[3])

	result[0] = c.gl.AddExtension(t01123, t01)
	result[1] = c.gl.AddExtension(t01123, c.gl.AddExtension(x[2], x[2]))
	result[2] = c.gl.AddExtension(t01233, t23)
	result[3] = c.gl.AddExtension(t01233, c.gl.AddExtension(x[0], x[0]))

	return result
}

func (c *GoldilocksChip) AddRCExtension(state GoldilocksStateExtension, round int) GoldilocksStateExtension {
	if round >= len(EXTERNAL_CONSTANTS) {
		panic("round index out of range in AddRCExtension")
	}

	for i := 0; i < WIDTH; i++ {
		rc := gl.NewVariable(EXTERNAL_CONSTANTS[round][i])
		rcQE := gl.NewQuadraticExtensionVariable(rc, gl.Zero())
		state[i] = c.gl.AddExtension(state[i], rcQE)
	}

	return state
}

func (c *GoldilocksChip) InternalLinearLayerExtension(state GoldilocksStateExtension) GoldilocksStateExtension {
	sum := gl.ZeroExtension()
	for i := 0; i < WIDTH; i++ {
		sum = c.gl.AddExtension(sum, state[i])
	}

	for i := 0; i < WIDTH; i++ {
		x := state[i]
		m := gl.NewVariable(MATRIX_DIAG_12_U64[i]).ToQuadraticExtension()
		state[i] = c.gl.AddExtension(sum, c.gl.MulExtension(x, m))
	}

	return state
}

func (c *GoldilocksChip) AddInternalConstantExtension(x gl.QuadraticExtensionVariable, round int) gl.QuadraticExtensionVariable {
	if round >= len(INTERNAL_CONSTANTS) {
		panic("round index out of range in AddInternalConstantExtension")
	}

	rc := gl.NewVariable(INTERNAL_CONSTANTS[round])
	rcQE := gl.NewQuadraticExtensionVariable(rc, gl.Zero())
	return c.gl.AddExtension(x, rcQE)
}

func (c *GoldilocksChip) SBoxPExtension(x gl.QuadraticExtensionVariable) gl.QuadraticExtensionVariable {
	x2 := c.gl.MulExtension(x, x)
	x4 := c.gl.MulExtension(x2, x2)
	x3 := c.gl.MulExtension(x, x2)
	return c.gl.MulExtension(x4, x3)
}

func (c *GoldilocksChip) SBoxLayerExtension(state GoldilocksStateExtension) GoldilocksStateExtension {
	for i := 0; i < WIDTH; i++ {
		state[i] = c.SBoxPExtension(state[i])
	}
	return state
}
