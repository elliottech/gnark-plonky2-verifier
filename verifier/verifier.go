package verifier

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/elliottech/gnark-plonky2-verifier/challenger"
	"github.com/elliottech/gnark-plonky2-verifier/fri"
	gl "github.com/elliottech/gnark-plonky2-verifier/goldilocks"
	"github.com/elliottech/gnark-plonky2-verifier/plonk"
	"github.com/elliottech/gnark-plonky2-verifier/poseidon"
	"github.com/elliottech/gnark-plonky2-verifier/types"
	"github.com/elliottech/gnark-plonky2-verifier/variables"
)

type VerifierChip struct {
	api               frontend.API             `gnark:"-"`
	glChip            *gl.Chip                 `gnark:"-"`
	poseidonGlChip    *poseidon.GoldilocksChip `gnark:"-"`
	poseidonBN254Chip *poseidon.BN254Chip      `gnark:"-"`
	plonkChip         *plonk.PlonkChip         `gnark:"-"`
	friChip           *fri.Chip                `gnark:"-"`
	commonData        types.CommonCircuitData  `gnark:"-"`
}

func NewVerifierChip(api frontend.API, commonCircuitData types.CommonCircuitData) *VerifierChip {
	glChip := gl.New(api)
	friChip := fri.NewChip(api, &commonCircuitData, &commonCircuitData.FriParams)
	plonkChip := plonk.NewPlonkChip(api, commonCircuitData)
	poseidonGlChip := poseidon.NewGoldilocksChip(api)
	poseidonBN254Chip := poseidon.NewBN254Chip(api)
	return &VerifierChip{
		api:               api,
		glChip:            glChip,
		poseidonGlChip:    poseidonGlChip,
		poseidonBN254Chip: poseidonBN254Chip,
		plonkChip:         plonkChip,
		friChip:           friChip,
		commonData:        commonCircuitData,
	}
}

func (c *VerifierChip) GetPublicInputsHash(publicInputs []gl.Variable) poseidon.GoldilocksHashOut {
	return c.poseidonGlChip.HashNoPad(publicInputs)
}

func (c *VerifierChip) GetChallenges(
	proof variables.Proof,
	publicInputsHash poseidon.GoldilocksHashOut,
	verifierData variables.VerifierOnlyCircuitData,
) variables.ProofChallenges {
	config := c.commonData.Config
	numChallenges := config.NumChallenges
	challenger := challenger.NewChip(c.api)

	challenger.ObserveElement(gl.NewVariable(config.FriConfig.RateBits))
	challenger.ObserveElement(gl.NewVariable(config.FriConfig.CapHeight))
	challenger.ObserveElement(gl.NewVariable(config.FriConfig.ProofOfWorkBits))
	/*
		Observe FRI reduction strategy.
		There are 3 types of reduction strategies: Fixed, ConstantArityBits, and MinSize. We only
		support ConstantArityBits for now. This code must be updated, as well as common circuit data
		deserialization; should other strategies are used for the wrapper circuit.
		Prepend F::ONE to arity bits like plonky2, representing ConstantArityBits.
	*/
	challenger.ObserveElement(gl.One())
	for _, bit := range config.FriConfig.ReductionStrategy.ConstantArityBits {
		challenger.ObserveElement(gl.NewVariable(bit))
	}
	challenger.ObserveElement(gl.NewVariable(config.FriConfig.NumQueryRounds))

	challenger.ObserveElement(gl.NewVariable(c.friChip.FriParams.Hiding))
	challenger.ObserveElement(gl.NewVariable(c.friChip.FriParams.DegreeBits))
	for _, v := range c.friChip.FriParams.ReductionArityBits {
		challenger.ObserveElement(gl.NewVariable(v))
	}

	fmt.Println()
	fmt.Println("GetChallenges test")
	fmt.Println()
	fmt.Println("config.FriConfig.RateBits:", config.FriConfig.RateBits)
	fmt.Println("config.FriConfig.CapHeight:", config.FriConfig.CapHeight)
	fmt.Println("config.FriConfig.ProofOfWorkBits:", config.FriConfig.ProofOfWorkBits)
	fmt.Println("config.FriConfig.ReductionStrategy.ConstantArityBits:", config.FriConfig.ReductionStrategy.ConstantArityBits)
	fmt.Println("config.FriConfig.NumQueryRounds:", config.FriConfig.NumQueryRounds)
	fmt.Println("friChip.FriParams.Hiding:", c.friChip.FriParams.Hiding)
	fmt.Println("friChip.FriParams.DegreeBits:", c.friChip.FriParams.DegreeBits)
	fmt.Println("friChip.FriParams.ReductionArityBits:", c.friChip.FriParams.ReductionArityBits)
	fmt.Println()

	fmt.Println()
	fmt.Println("Field elements")
	fmt.Println()
	fmt.Println("config.FriConfig.RateBits:", gl.NewVariable(config.FriConfig.RateBits))
	fmt.Println("config.FriConfig.CapHeight:", gl.NewVariable(config.FriConfig.CapHeight))
	fmt.Println("config.FriConfig.ProofOfWorkBits:", gl.NewVariable(config.FriConfig.ProofOfWorkBits))
	fmt.Println("config.FriConfig.NumQueryRounds:", gl.NewVariable(config.FriConfig.NumQueryRounds))
	fmt.Println("friChip.FriParams.Hiding:", gl.NewVariable(c.friChip.FriParams.Hiding))
	fmt.Println("friChip.FriParams.DegreeBits:", gl.NewVariable(c.friChip.FriParams.DegreeBits))
	fmt.Println()

	var circuitDigest = verifierData.CircuitDigest

	challenger.ObserveBN254Hash(circuitDigest)
	challenger.ObserveHash(publicInputsHash)
	challenger.ObserveCap(proof.WiresCap)
	plonkBetas := challenger.GetNChallenges(numChallenges)
	plonkGammas := challenger.GetNChallenges(numChallenges)

	challenger.ObserveCap(proof.PlonkZsPartialProductsCap)
	plonkAlphas := challenger.GetNChallenges(numChallenges)

	challenger.ObserveCap(proof.QuotientPolysCap)
	plonkZeta := challenger.GetExtensionChallenge()

	challenger.ObserveOpenings(c.friChip.ToOpenings(proof.Openings))

	return variables.ProofChallenges{
		PlonkBetas:  plonkBetas,
		PlonkGammas: plonkGammas,
		PlonkAlphas: plonkAlphas,
		PlonkZeta:   plonkZeta,
		FriChallenges: challenger.GetFriChallenges(
			proof.OpeningProof.CommitPhaseMerkleCaps,
			proof.OpeningProof.FinalPoly,
			proof.OpeningProof.PowWitness,
			config.FriConfig,
		),
	}
}

func (c *VerifierChip) rangeCheckProof(proof variables.Proof) {
	// Need to verify the plonky2 proof's openings, openings proof (other than the sibling elements), fri's final poly, pow witness.

	// Note that this is NOT range checking the public inputs (first 32 elements should be no more than 8 bits and the last 4 elements should be no more than 64 bits).  Since this is currently being inputted via the smart contract,
	// we will assume that caller is doing that check.

	// Range check the proof's openings.
	for _, constant := range proof.Openings.Constants {
		c.glChip.RangeCheckQE(constant)
	}

	for _, plonkSigma := range proof.Openings.PlonkSigmas {
		c.glChip.RangeCheckQE(plonkSigma)
	}

	for _, wire := range proof.Openings.Wires {
		c.glChip.RangeCheckQE(wire)
	}

	for _, plonkZ := range proof.Openings.PlonkZs {
		c.glChip.RangeCheckQE(plonkZ)
	}

	for _, plonkZNext := range proof.Openings.PlonkZsNext {
		c.glChip.RangeCheckQE(plonkZNext)
	}

	for _, partialProduct := range proof.Openings.PartialProducts {
		c.glChip.RangeCheckQE(partialProduct)
	}

	for _, quotientPoly := range proof.Openings.QuotientPolys {
		c.glChip.RangeCheckQE(quotientPoly)
	}

	// Range check the openings proof.
	for _, queryRound := range proof.OpeningProof.QueryRoundProofs {
		for _, evalsProof := range queryRound.InitialTreesProof.EvalsProofs {
			for _, evalsProofElement := range evalsProof.Elements {
				c.glChip.RangeCheck(evalsProofElement)
			}
		}

		for _, queryStep := range queryRound.Steps {
			for _, eval := range queryStep.Evals {
				c.glChip.RangeCheckQE(eval)
			}
		}
	}

	// Range check the fri's final poly.
	for _, coeff := range proof.OpeningProof.FinalPoly.Coeffs {
		c.glChip.RangeCheckQE(coeff)
	}

	// Range check the pow witness.
	c.glChip.RangeCheck(proof.OpeningProof.PowWitness)
}

func (c *VerifierChip) Verify(
	proof variables.Proof,
	publicInputs []gl.Variable,
	verifierData variables.VerifierOnlyCircuitData,
) {
	c.rangeCheckProof(proof)

	// Generate the parts of the witness that is for the plonky2 proof input
	publicInputsHash := c.GetPublicInputsHash(publicInputs)
	proofChallenges := c.GetChallenges(proof, publicInputsHash, verifierData)

	c.plonkChip.Verify(proofChallenges, proof.Openings, publicInputsHash)

	initialMerkleCaps := []variables.FriMerkleCap{
		verifierData.ConstantSigmasCap,
		proof.WiresCap,
		proof.PlonkZsPartialProductsCap,
		proof.QuotientPolysCap,
	}

	c.friChip.VerifyFriProof(
		c.friChip.GetInstance(proofChallenges.PlonkZeta),
		c.friChip.ToOpenings(proof.Openings),
		&proofChallenges.FriChallenges,
		initialMerkleCaps,
		&proof.OpeningProof,
	)
}
