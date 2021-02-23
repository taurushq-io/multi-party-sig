package cmpold

import "time"

type Debug struct {
	N, ID int

	TimeRound1, TimeRound2, TimeRound3, TimeRound4, TimeRound5 time.Duration
}
