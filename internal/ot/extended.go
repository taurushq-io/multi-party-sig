package ot

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/zeebo/blake3"
)

const fieldElementLen = 2 * params.OTBytes / 8

type fieldElement [fieldElementLen]uint64

func (f *fieldElement) eq(a *fieldElement) bool {
	acc := uint64(0)
	for i := 0; i < fieldElementLen; i++ {
		acc |= f[i] ^ a[i]
	}
	return ((acc | -acc) >> (63)) != 1
}

func (f *fieldElement) shl1() {
	for i := fieldElementLen - 1; i > 0; i-- {
		f[i] = (f[i] << 1) | (f[i-1] >> 63)
	}
	f[0] <<= 1
}

func (f *fieldElement) accumulate(a *[params.OTBytes]byte, b *[params.OTBytes]byte) {
	var b64 [params.OTBytes / 8]uint64
	for i := 0; i < len(b64); i++ {
		b64[i] = binary.LittleEndian.Uint64(b[8*i : 8*(i+1)])
	}
	var a64 [params.OTBytes / 8]uint64
	for i := 0; i < len(a64); i++ {
		a64[i] = binary.LittleEndian.Uint64(a[8*i : 8*(i+1)])
	}
	var scratch fieldElement
	for i := 0; i < fieldElementLen; i++ {
		scratch[i] = 0
	}

	for i := 63; i >= 0; i-- {
		for j := 0; j < len(b64); j++ {
			mask := -((a64[j] >> i) & 1)
			for k := 0; k < len(b64); k++ {
				scratch[j+k] ^= mask & b64[k]
			}
		}
		if i != 0 {
			scratch.shl1()
		}
	}

	for i := 0; i < fieldElementLen; i++ {
		f[i] ^= scratch[i]
	}
}

type ExtendedOTSendResult struct {
	_V0 [][params.OTBytes]byte
	_V1 [][params.OTBytes]byte
}

func ExtendedOTSend(ctxHash *hash.Hash, setup *CorreOTSendSetup, batchSize int, msg *ExtendedOTReceiveMessage) (*ExtendedOTSendResult, error) {
	inflatedBatchSize := batchSize + params.OTParam + params.StatParam

	correResult, err := CorreOTSend(ctxHash, setup, inflatedBatchSize, msg.CorreMsg)
	if err != nil {
		return nil, err
	}

	for i := 0; i < params.OTParam; i++ {
		ctxHash.WriteAny(correResult._U[i])
	}

	chi := make([][params.OTBytes]byte, inflatedBatchSize)
	digest := ctxHash.Digest()
	for i := 0; i < len(chi); i++ {
		_, _ = digest.Read(chi[i][:])
	}

	var q fieldElement
	for i := 0; i < len(chi); i++ {
		q.accumulate(&correResult._Q[i], &chi[i])
	}

	q.accumulate(&msg.X, &setup._Delta)

	if !q.eq(&msg.T) {
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

type ExtendedOTReceiveResult struct {
	_VChoices [][params.OTBytes]byte
}

type ExtendedOTReceiveMessage struct {
	CorreMsg *CorreOTReceiveMessage
	X        [params.OTBytes]byte
	T        fieldElement
}

func ExtendedOTReceive(ctxHash *hash.Hash, setup *CorreOTReceiveSetup, choices []byte) (*ExtendedOTReceiveMessage, *ExtendedOTReceiveResult) {
	inflatedBatchSize := 8*len(choices) + params.OTParam + params.StatParam
	extraChoices := make([]byte, inflatedBatchSize/8)
	copy(extraChoices, choices)
	_, _ = rand.Read(extraChoices[len(choices):])

	correMsg, correResult := CorreOTReceive(ctxHash, setup, extraChoices)

	for i := 0; i < params.OTParam; i++ {
		ctxHash.WriteAny(correMsg.U[i])
	}
	outMsg := new(ExtendedOTReceiveMessage)
	outMsg.CorreMsg = correMsg

	chi := make([][params.OTBytes]byte, inflatedBatchSize)
	digest := ctxHash.Digest()
	for i := 0; i < len(chi); i++ {
		_, _ = digest.Read(chi[i][:])
	}

	for i := 0; i < len(chi); i++ {
		mask := -bitAt(i, extraChoices)
		for j := 0; j < params.OTBytes; j++ {
			outMsg.X[j] ^= mask & chi[i][j]
		}
	}

	for i := 0; i < len(chi) && i < len(correResult._T); i++ {
		outMsg.T.accumulate(&correResult._T[i], &chi[i])
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
