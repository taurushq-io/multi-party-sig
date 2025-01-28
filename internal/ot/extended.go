package ot

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/zeebo/blake3"
)

const fieldElementLen = params.OTBytes / 8

type fieldElement [fieldElementLen]uint64

func randFe(r io.Reader) fieldElement {
	var out fieldElement
	for i := 0; i < fieldElementLen; i++ {
		_ = binary.Read(r, binary.LittleEndian, &out[i])
	}
	return out
}

// doubleFieldElementLen is enough to hold 2 elements of GF(2^k).
//
// This allows us to multiply 2 elements together withour performing a reduction.
const doubleFieldElementLen = 2 * fieldElementLen

// doubleFieldElement represent an element of GF(2^k), in little endian order.
type doubleFieldElement [doubleFieldElementLen]uint64

// eq checks if two field elements are equal, in constant time.
func (f *doubleFieldElement) eq(a *doubleFieldElement) byte {
	acc := uint64(0)
	for i := 0; i < doubleFieldElementLen; i++ {
		acc |= f[i] ^ a[i]
	}
	return byte((acc|-acc)>>(63)) ^ 1
}

// shl1 shifts a field element left by 1 bit.
func (f *doubleFieldElement) shl1() {
	for i := doubleFieldElementLen - 1; i > 0; i-- {
		f[i] = (f[i] << 1) | (f[i-1] >> 63)
	}
	f[0] <<= 1
}

func (f *fieldElement) shl1() {
	for i := fieldElementLen - 1; i > 0; i-- {
		f[i] = (f[i] << 1) | (f[i-1] >> 63)
	}
	f[0] <<= 1
}

// accumulate calculates f += a * b, in the GF(2^k) field.
//
// This allows us to calculate a weight sum of different vectors, which we use
// to detect cheating in the protocol.
func (f *doubleFieldElement) accumulate(a fieldElement, b fieldElement) {
	var scratch doubleFieldElement
	for i := 0; i < doubleFieldElementLen; i++ {
		scratch[i] = 0
	}

	for i := 63; i >= 0; i-- {
		for j := 0; j < len(b); j++ {
			mask := -((a[j] >> i) & 1)
			for k := 0; k < len(b); k++ {
				scratch[j+k] ^= mask & b[k]
			}
		}
		if i != 0 {
			scratch.shl1()
		}
	}

	for i := 0; i < doubleFieldElementLen; i++ {
		f[i] ^= scratch[i]
	}
}

// conditionalAdd adds x if the first bit of choice is 1, in constant time.
func (f *doubleFieldElement) conditionalAdd(choice byte, x doubleFieldElement) {
	for i := 0; i < doubleFieldElementLen; i++ {
		f[i] ^= (-uint64(choice & 1)) & x[i]
	}
}

func pluckColumnToFieldElement(data [][params.OTBytes]byte, c int) fieldElement {
	var out fieldElement
	for i := 0; i < params.OTParam; i++ {
		out.shl1()
		// out |= data[i][c] (indexing into the bit)
		out[0] |= uint64(bitAt(c, data[i][:]))
	}
	return out
}

func pluckBitsToFieldElements(data []byte) []fieldElement {
	out := make([]fieldElement, (8*len(data))/params.OTParam)
	for i := 0; i < len(out); i++ {
		for j := 0; j < params.OTParam; j++ {
			out[i].shl1()
			out[i][0] |= uint64(bitAt(params.OTParam*i+j, data))
		}
	}
	return out
}

// transposeToFieldSize elements transposes matrix columns into field elements.
//
// We should have a matrix with lambda columns, and N * lambda rows. We end up
// with N rows, each of which contains lambda field element sized arrays.
func transposeToFieldSizeElements(data [][params.OTBytes]byte) [][params.OTParam]fieldElement {
	out := make([][params.OTParam]fieldElement, len(data)/params.OTParam)
	for i := 0; i < len(out); i++ {
		for c := 0; c < params.OTParam; c++ {
			// Pick out a column of bits from lambda rows, and turn that into a field element.
			out[i][c] = pluckColumnToFieldElement(data[params.OTParam*i:params.OTParam*(i+1)], c)
		}
	}
	return out
}

// adjustBatchSize pads the desired batch size to a suitable length
func adjustBatchSize(desired int) int {
	// c.f. https://github.com/cronokirby/cait-sith/blob/8e6dc86d1a6c672315a7391c3f0cb3c58c990f3f/src/triples/random_ot_extension.rs#L35
	r := desired % params.OTParam
	// padded should be a multiple of the security parameter
	padded := desired
	if r != 0 {
		padded += (params.OTParam - r)
	}
	return padded + 2*params.OTParam
}

// ExtendedOTSendResult is the Sender's result for an Extended OT.
//
// The Sender receives two batches of random vectors, and the Receiver receives a batch
// of selections from these random vectors.
type ExtendedOTSendResult struct {
	_V0 [][params.OTBytes]byte
	_V1 [][params.OTBytes]byte
}

// ExtendedOTSend runs the Sender's side of the Extended OT Protocol.
//
// The goal of this protocol is to conduct a large number of random oblivious transfers.
//
// This follows Figure 7 of https://eprint.iacr.org/2015/546.
//
// A single setup can be used for many invocations of this protocol, so long as the
// hash is initialized with some kind of nonce.
func ExtendedOTSend(ctxHash *hash.Hash, setup *CorreOTSendSetup, batchSize int, msg *ExtendedOTReceiveMessage) (*ExtendedOTSendResult, error) {
	adjustedBatchSize := adjustBatchSize(batchSize)

	correResult, err := CorreOTSend(ctxHash, setup, adjustedBatchSize, msg.CorreMsg)
	if err != nil {
		return nil, err
	}

	for i := 0; i < params.OTParam; i++ {
		ctxHash.WriteAny(correResult._U[i])
	}

	chi := make([]fieldElement, adjustedBatchSize/params.OTParam)
	digest := ctxHash.Digest()
	for i := 0; i < len(chi); i++ {
		chi[i] = randFe(digest)
	}

	good := byte(1)
	_Qhat := transposeToFieldSizeElements(correResult._Q)
	for j := 0; j < params.OTParam; j++ {
		var q doubleFieldElement
		for i := 0; i < len(chi); i++ {
			q.accumulate(_Qhat[i][j], chi[i])
		}
		expected := msg.T[j]
		expected.conditionalAdd(bitAt(j, setup._Delta[:]), msg.X)
		good &= q.eq(&expected)
	}

	if good != 1 {
		return nil, fmt.Errorf("ExtendedOTSend: monochrome check failed")
	}

	V0 := make([][params.OTBytes]byte, batchSize)
	V1 := make([][params.OTBytes]byte, batchSize)
	hasher := blake3.New()
	ctr := make([]byte, 4)
	for i := 0; i < batchSize; i++ {
		binary.BigEndian.PutUint32(ctr, uint32(i))

		hasher.Reset()
		hasher.Write(ctr)
		hasher.Write(correResult._Q[i][:])
		hasher.Digest().Read(V0[i][:])

		for j := 0; j < params.OTBytes; j++ {
			correResult._Q[i][j] ^= setup._Delta[j]
		}
		hasher.Reset()
		hasher.Write(ctr)
		hasher.Write(correResult._Q[i][:])
		hasher.Digest().Read(V1[i][:])
	}

	return &ExtendedOTSendResult{_V0: V0, _V1: V1}, nil
}

// ExtendedOTReceiveResult is the Receiver's result for an Extended OT.
//
// We receive the random vectors corresponding to our choice bits.
type ExtendedOTReceiveResult struct {
	_VChoices [][params.OTBytes]byte
}

// ExtendedOTReceiveMessage is the Receiver's first message for an Extended OT.
type ExtendedOTReceiveMessage struct {
	CorreMsg *CorreOTReceiveMessage
	X        doubleFieldElement
	T        [params.OTParam]doubleFieldElement
}

// ExtendedOTReceive runs the Receiver's side of the Extended OT Protocol.
//
// The goal of this protocol is to conduct a large number of random oblivious transfers.
//
// This follows Figure 7 of https://eprint.iacr.org/2015/546.
//
// A single setup can be used for many invocations of this protocol, so long as the
// hash is initialized with some kind of nonce.
func ExtendedOTReceive(ctxHash *hash.Hash, setup *CorreOTReceiveSetup, choices []byte) (*ExtendedOTReceiveMessage, *ExtendedOTReceiveResult) {
	adjustedBatchSize := adjustBatchSize(8 * len(choices))
	extraChoices := make([]byte, adjustedBatchSize/8)
	copy(extraChoices, choices)
	_, _ = rand.Read(extraChoices[len(choices):])

	correMsg, correResult := CorreOTReceive(ctxHash, setup, extraChoices)

	for i := 0; i < params.OTParam; i++ {
		ctxHash.WriteAny(correMsg.U[i])
	}
	outMsg := new(ExtendedOTReceiveMessage)
	outMsg.CorreMsg = correMsg

	chi := make([]fieldElement, adjustedBatchSize/params.OTParam)
	digest := ctxHash.Digest()
	for i := 0; i < len(chi); i++ {
		chi[i] = randFe(digest)
	}

	bHat := pluckBitsToFieldElements(extraChoices)
	_THat := transposeToFieldSizeElements(correResult._T)

	for i := 0; i < len(chi); i++ {
		outMsg.X.accumulate(bHat[i], chi[i])
		for j := 0; j < params.OTParam; j++ {
			outMsg.T[j].accumulate(_THat[i][j], chi[i])
		}
	}

	VChoices := make([][params.OTBytes]byte, 8*len(choices))
	hasher := blake3.New()
	ctr := make([]byte, 4)
	for i := 0; i < len(VChoices); i++ {
		hasher.Reset()
		binary.BigEndian.PutUint32(ctr, uint32(i))
		_, _ = hasher.Write(ctr)
		_, _ = hasher.Write(correResult._T[i][:])
		_, _ = hasher.Digest().Read(VChoices[i][:])
	}

	return outMsg, &ExtendedOTReceiveResult{_VChoices: VChoices}
}
