package bip32

import (
	"fmt"
	"strconv"
	"strings"
)

type Path struct {
	indices []uint32
}

func newIndex(relativeIndex uint32, hardened bool) uint32 {
	hardenedBit := uint32(1 << 31)

	if relativeIndex&hardenedBit == 1 {
		panic(fmt.Sprintf("Expected index less than 2^31, found %d", relativeIndex))
	}

	if hardened {
		return hardenedBit | relativeIndex
	} else {
		return relativeIndex
	}
}

func indexFrom(spec string) (uint32, error) {
	hardenedSuffix := "'"
	hardened := strings.HasSuffix(spec, hardenedSuffix)
	spec = strings.TrimSuffix(spec, hardenedSuffix)

	base := 10
	bitSize := 31
	index, err := strconv.ParseUint(spec, base, bitSize)
	if err != nil {
		var i uint32
		return i, err
	}

	return newIndex(uint32(index), hardened), nil
}

func PathFrom(spec string) (Path, error) {
	var indices []uint32

	if len(spec) == 0 {
		return Path{indices: indices}, nil
	}

	for _, s := range strings.Split(spec, "/") {
		h, err := indexFrom(s)
		if err != nil {
			var p Path
			return p, err
		}

		indices = append(indices, h)
	}

	return Path{indices: indices}, nil
}
