package test

import (
	"fmt"
	"log"
	"reflect"
	"sync"

	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/internal/broadcast"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"golang.org/x/sync/errgroup"
)

type Rule interface {
	ModifyBefore(rPrevious round.Round)
	ModifyAfter(rNext round.Round)
	ModifyContent(rNext round.Round, to party.ID, content round.Content)
}

func Rounds(group curve.Curve, rounds map[party.ID]round.Round, culprit party.ID, rule Rule) (error, bool) {
	N := len(rounds)
	var errGroup errgroup.Group

	roundType, err := checkAllRoundsSame(rounds, culprit)
	if err != nil {
		return err, false
	}
	log.Println(roundType, "finalizing")
	mtx := new(sync.Mutex)
	// get the second set of  messages
	out := make(chan *round.Message, N*N)
	for id := range rounds {
		f := func(id party.ID, rounds map[party.ID]round.Round) func() error {
			return func() (err error) {
				var rNew, rNewReal round.Round
				r := rounds[id]
				rReal := getRound(r)
				if id == culprit {
					rule.ModifyBefore(rReal)
					outFake := make(chan *round.Message, N)
					rNew, err = r.Finalize(outFake)
					close(outFake)
					rule.ModifyAfter(rReal)
					rNewReal = getRound(rNew)
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
					mtx.Lock()
					rounds[id] = rNew
					mtx.Unlock()
				}
				return nil
			}
		}
		errGroup.Go(f(id, rounds))
	}
	if err = errGroup.Wait(); err != nil {
		return err, false
	}
	close(out)

	roundType, err = checkAllRoundsSame(rounds, culprit)
	if err != nil {
		return err, false
	}
	if roundType.String() == reflect.TypeOf(&round.Output{}).String() {
		return nil, true
	}

	log.Println(roundType, "verifying")

	for msg := range out {
		msgBytes, err := cbor.Marshal(msg)
		if err != nil {
			return err, false
		}
		for id := range rounds {
			f := func(id party.ID, msgBytes []byte) func() error {
				return func() (err error) {
					r := rounds[id]
					var m round.Message
					m.Content = r.MessageContent()
					m.Content.Init(group)
					if err = cbor.Unmarshal(msgBytes, &m); err != nil {
						return err
					}
					if m.From != id && (m.To == "" || m.To == id) {
						err = r.VerifyMessage(m)
						if err != nil && id != culprit {
							return err
						}
						mtx.Lock()
						err = r.StoreMessage(m)
						mtx.Unlock()
						if err != nil && id != culprit {
							return err
						}
					}
					return nil
				}
			}
			errGroup.Go(f(id, msgBytes))
		}
	}

	return errGroup.Wait(), false
}

func getAnyRound(rounds map[party.ID]round.Round) round.Round {
	for _, r := range rounds {
		return r
	}
	return nil
}

func checkAllRoundsSame(rounds map[party.ID]round.Round, culprit party.ID) (reflect.Type, error) {
	var t reflect.Type
	for id, r := range rounds {
		if id == culprit {
			continue
		}
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

func getRound(outerRound round.Round) round.Round {
	switch r := outerRound.(type) {
	case *broadcast.Round1:
		return getRound(r.Round)
	case *broadcast.Round2:
		return getRound(r.Round)
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
