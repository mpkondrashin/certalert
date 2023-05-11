package sms

import (
	"errors"
	"fmt"
)

var ErrUnknownPriority = errors.New("unknown priority")

type DistributionPiority int

const (
	PriorityLow DistributionPiority = iota
	PriorityHigh
)

var DistributionPiorityString = []string{"low", "high"}

func (d DistributionPiority) String() string {
	return DistributionPiorityString[d]
}

func DistributionPiorityFromString(s string) (DistributionPiority, error) {
	switch s {
	case "low":
		return PriorityLow, nil
	case "high":
		return PriorityHigh, nil
	default:
		return PriorityLow, fmt.Errorf("\"%s\": %w", s, ErrUnknownPriority)
	}
}
