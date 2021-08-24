package test

import (
	"fmt"
	"log"
	"reflect"

	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/internal/broadcast"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"golang.org/x/sync/errgroup"
)

type Rule interface {
	ModifyBefore(rPrevious round.Session)
	ModifyAfter(rNext round.Session)
	ModifyContent(rNext round.Session, to party.ID, content round.Content)
}

func Rounds(group curve.Curve, rounds []round.Session, rule Rule) (error, bool) {
	N := len(rounds)

	roundType, err := checkAllRoundsSame(rounds)
	if err != nil {
		return err, false
	}
	log.Println(roundType, "finalizing")
	// get the second set of  messages
	errGroup := new(errgroup.Group)
	out := make(chan *round.Message, N*N)
	for id := range rounds {
		idx := id
		r := rounds[idx]
		errGroup.Go(func() error {
			var rNew, rNewReal round.Session
			if rule != nil {
				rReal := getRound(r)
				rule.ModifyBefore(rReal)
				outFake := make(chan *round.Message, N)
				rNew, err = r.Finalize(outFake)
				close(outFake)
				rNewReal = getRound(rNew)
				rule.ModifyAfter(rNewReal)
				for msg := range outFake {
					rule.ModifyContent(rNewReal, msg.To, getContent(msg.Content))
					out <- msg
				}
			} else {
				rNew, err = r.Finalize(out)
			}

			if err != nil {
				return err
			}

			if rNew != nil {
				rounds[idx] = rNew
			}
			return nil
		})
	}
	if err = errGroup.Wait(); err != nil {
		return err, false
	}
	close(out)

	roundType, err = checkAllRoundsSame(rounds)
	if err != nil {
		return err, false
	}
	if roundType.String() == reflect.TypeOf(&round.Output{}).String() {
		return nil, true
	}

	log.Println(roundType, "verifying")

	var msgBytes []byte
	for msg := range out {
		msgBytes, err = cbor.Marshal(msg)
		if err != nil {
			return err, false
		}
		for idx := range rounds {
			r := rounds[idx]
			errGroup.Go(func() error {
				var m round.Message

				m.Content = r.MessageContent()
				m.Content.Init(group)
				err = cbor.Unmarshal(msgBytes, &m)
				if err != nil {
					return err
				}
				if m.From != r.SelfID() && (m.To == "" || m.To == r.SelfID()) {
					if err = r.VerifyMessage(m); err != nil {
						return err
					}
					if err = r.StoreMessage(m); err != nil {
						return err
					}
				}
				return nil
			})
		}
		if err = errGroup.Wait(); err != nil {
			return err, false
		}
	}

	return nil, false
}

func checkAllRoundsSame(rounds []round.Session) (reflect.Type, error) {
	var t reflect.Type
	for _, r := range rounds {
		rReal := getRound(r)
		t2 := reflect.TypeOf(rReal)
		if t == nil {
			t = t2
		} else if t != t2 {
			return t, fmt.Errorf("two different rounds: %s %s", t, t2)
		}
	}
	return t, nil
}

func getRound(outerRound round.Session) round.Session {
	switch r := outerRound.(type) {
	case *broadcast.Round1:
		return getRound(r.Session)
	case *broadcast.Round2:
		return getRound(r.Session)
	default:
		return r
	}
}

func getContent(outerContent round.Content) round.Content {
	switch content := outerContent.(type) {
	case *broadcast.Message2:
		return getContent(content.Content)
	default:
		return content
	}
}
