package test

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"golang.org/x/sync/errgroup"
)

// Rule describes various hooks that can be applied to a protocol execution.
type Rule interface {
	// ModifyBefore modifies r before r.Finalize() is called.
	ModifyBefore(r round.Session)
	// ModifyAfter modifies rNext, which is the round returned by r.Finalize().
	ModifyAfter(rNext round.Session)
	// ModifyContent modifies content for the message that is delivered in rNext.
	ModifyContent(rNext round.Session, to party.ID, content round.Content)
}

func Rounds(rounds []round.Session, rule Rule) (error, bool) {
	var (
		err       error
		roundType reflect.Type
		errGroup  errgroup.Group
		N         = len(rounds)
		out       = make(chan *round.Message, N*(N+1))
	)

	if roundType, err = checkAllRoundsSame(rounds); err != nil {
		return err, false
	}
	// get the second set of messages
	for id := range rounds {
		idx := id
		r := rounds[idx]
		errGroup.Go(func() error {
			var rNew, rNewReal round.Session
			if rule != nil {
				rReal := getRound(r)
				rule.ModifyBefore(rReal)
				outFake := make(chan *round.Message, N+1)
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

	// Check that all rounds are the same type
	if roundType, err = checkAllRoundsSame(rounds); err != nil {
		return err, false
	}
	if roundType.String() == reflect.TypeOf(&round.Output{}).String() {
		return nil, true
	}
	if roundType.String() == reflect.TypeOf(&round.Abort{}).String() {
		return nil, true
	}

	for msg := range out {
		msgBytes, err := cbor.Marshal(msg.Content)
		if err != nil {
			return err, false
		}
		for _, r := range rounds {
			m := *msg
			r := r
			if msg.From == r.SelfID() || msg.Content.RoundNumber() != r.Number() {
				continue
			}
			errGroup.Go(func() error {
				if m.Broadcast {
					b, ok := r.(round.BroadcastRound)
					if !ok {
						return errors.New("broadcast message but not broadcast round")
					}
					m.Content = b.BroadcastContent()
					if err = cbor.Unmarshal(msgBytes, m.Content); err != nil {
						return err
					}

					if err = b.StoreBroadcastMessage(m); err != nil {
						return err
					}
				} else {
					m.Content = r.MessageContent()
					if err = cbor.Unmarshal(msgBytes, m.Content); err != nil {
						return err
					}

					if m.To == "" || m.To == r.SelfID() {
						if err = r.VerifyMessage(m); err != nil {
							return err
						}
						if err = r.StoreMessage(m); err != nil {
							return err
						}
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
	return outerRound
}

func getContent(outerContent round.Content) round.Content {
	return outerContent
}
