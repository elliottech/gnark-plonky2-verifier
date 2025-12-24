package gates

import (
	"regexp"

	"github.com/consensys/gnark/frontend"
	gl "github.com/elliottech/gnark-plonky2-verifier/goldilocks"
	"github.com/elliottech/gnark-plonky2-verifier/poseidon"
	"github.com/elliottech/gnark-plonky2-verifier/poseidon2"
)

var poseidon2GateRegex = regexp.MustCompile("Poseidon2Gate.*")

func deserializePoseidon2Gate(parameters map[string]string) Gate {
	// Has the format "Poseidon2Gate(PhantomData<plonky2_field::goldilocks_field::GoldilocksField>)<WIDTH=12>"
	return NewPoseidon2Gate()
}

type Poseidon2Gate struct {
}

func NewPoseidon2Gate() *Poseidon2Gate {
	return &Poseidon2Gate{}
}

func (g *Poseidon2Gate) Id() string {
	return "Poseidon2Gate"
}

func (g *Poseidon2Gate) WireInput(i uint64) uint64 {
	return i
}

func (g *Poseidon2Gate) WireOutput(i uint64) uint64 {
	return poseidon2.WIDTH + i
}

func (g *Poseidon2Gate) WireSwap() uint64 {
	return 2 * poseidon2.WIDTH
}

func (g *Poseidon2Gate) WireDelta(i uint64) uint64 {
	if i >= 4 {
		panic("Delta index out of range")
	}
	if poseidon.SPONGE_WIDTH != poseidon2.WIDTH {
		panic("Poseidon and Poseidon2 SPONGE_WIDTH mismatch")
	}
	return START_DELTA + i
}

const START_ROUND_F_BEGIN = START_DELTA + 4

func (g *Poseidon2Gate) WireFullSBox0(round uint64, i uint64) uint64 {
	if round == 0 {
		panic("First-round S-box inputs are not stored as wires")
	}
	if round >= poseidon2.ROUNDS_F_HALF {
		panic("S-box input round out of range")
	}
	if i >= poseidon2.WIDTH {
		panic("S-box input index out of range")
	}

	return START_ROUND_F_BEGIN + (round-1)*poseidon2.WIDTH + i
}

func (g *Poseidon2Gate) WirePartialSBox(round uint64) uint64 {
	if round >= poseidon2.ROUNDS_P {
		panic("S-box input round out of range")
	}
	if START_PARTIAL != START_ROUND_F_BEGIN+(poseidon2.ROUNDS_F_HALF-1)*poseidon2.WIDTH {
		panic("START_PARTIAL offset mismatch")
	}
	return START_PARTIAL + round
}

const START_ROUND_F_END = START_PARTIAL + poseidon2.ROUNDS_P

func (g *Poseidon2Gate) WireFullSBox1(round uint64, i uint64) uint64 {
	if round >= poseidon2.ROUNDS_F_HALF {
		panic("S-box input round out of range")
	}
	if i >= poseidon2.WIDTH {
		panic("S-box input index out of range")
	}

	return START_ROUND_F_END + round*poseidon2.WIDTH + i
}

func (g *Poseidon2Gate) WiresEnd() uint64 {
	return START_ROUND_F_END + poseidon2.ROUNDS_F_HALF*poseidon2.WIDTH
}

func (g *Poseidon2Gate) EvalUnfiltered(
	api frontend.API,
	glApi *gl.Chip,
	vars EvaluationVars,
) []gl.QuadraticExtensionVariable {
	constraints := []gl.QuadraticExtensionVariable{}

	poseidon2Chip := poseidon2.NewGoldilocksChip(api)

	// Assert that `swap` is binary.
	swap := vars.localWires[g.WireSwap()]
	swapMinusOne := glApi.SubExtension(swap, gl.OneExtension())
	constraints = append(constraints, glApi.MulExtension(swap, swapMinusOne))

	// Assert that each delta wire is set properly: `delta_i = swap * (rhs - lhs)`.
	for i := uint64(0); i < 4; i++ {
		inputLhs := vars.localWires[g.WireInput(i)]
		inputRhs := vars.localWires[g.WireInput(i+4)]
		deltaI := vars.localWires[g.WireDelta(i)]
		diff := glApi.SubExtension(inputRhs, inputLhs)
		expectedDeltaI := glApi.MulExtension(swap, diff)
		constraints = append(constraints, glApi.SubExtension(expectedDeltaI, deltaI))
	}

	// Compute the possibly-swapped input layer.
	var state [poseidon2.WIDTH]gl.QuadraticExtensionVariable
	for i := uint64(0); i < 4; i++ {
		deltaI := vars.localWires[g.WireDelta(i)]
		inputLhs := vars.localWires[g.WireInput(i)]
		inputRhs := vars.localWires[g.WireInput(i+4)]
		state[i] = glApi.AddExtension(inputLhs, deltaI)
		state[i+4] = glApi.SubExtension(inputRhs, deltaI)
	}
	for i := uint64(8); i < poseidon2.WIDTH; i++ {
		state[i] = vars.localWires[g.WireInput(i)]
	}

	roundCounter := 0

	// The initial linear layer.
	state = poseidon2Chip.ExternalLinearLayerExtension(state)

	// The first half of the external rounds.
	for r := 0; r < poseidon2.ROUNDS_F_HALF; r++ {
		state = poseidon2Chip.AddRCExtension(state, r)
		if r != 0 {
			for i := uint64(0); i < poseidon2.WIDTH; i++ {
				sBoxIn := vars.localWires[g.WireFullSBox0(uint64(r), i)]
				constraints = append(constraints, glApi.SubExtension(state[i], sBoxIn))
				state[i] = sBoxIn
			}
		}
		state = poseidon2Chip.SBoxLayerExtension(state)
		state = poseidon2Chip.ExternalLinearLayerExtension(state)
		roundCounter++
	}

	// The internal rounds.
	for r := 0; r < poseidon2.ROUNDS_P; r++ {
		state[0] = poseidon2Chip.AddInternalConstantExtension(state[0], r)
		sBoxIn := vars.localWires[g.WirePartialSBox(uint64(r))]
		constraints = append(constraints, glApi.SubExtension(state[0], sBoxIn))
		state[0] = sBoxIn
		state[0] = poseidon2Chip.SBoxPExtension(state[0])
		state = poseidon2Chip.InternalLinearLayerExtension(state)
	}

	// The second half of the external rounds.
	for r := poseidon2.ROUNDS_F_HALF; r < poseidon2.ROUNDS_F; r++ {
		state = poseidon2Chip.AddRCExtension(state, r)
		if r != 0 {
			for i := uint64(0); i < poseidon2.WIDTH; i++ {
				sBoxIn := vars.localWires[g.WireFullSBox1(uint64(r-poseidon2.ROUNDS_F_HALF), i)]
				constraints = append(constraints, glApi.SubExtension(state[i], sBoxIn))
				state[i] = sBoxIn
			}
		}
		state = poseidon2Chip.SBoxLayerExtension(state)
		state = poseidon2Chip.ExternalLinearLayerExtension(state)
		roundCounter++
	}

	for i := uint64(0); i < poseidon2.WIDTH; i++ {
		constraints = append(constraints, glApi.SubExtension(state[i], vars.localWires[g.WireOutput(i)]))
	}

	return constraints
}
