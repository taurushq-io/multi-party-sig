package protocol

import (
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type EchoFailure struct {
	Round    round.Number
	Messages map[party.ID]*Message
}

type VerificationFailure struct {
	Messages []*Message
}

type DuplicateFailure struct {
	Message1, Message2 *Message
}
