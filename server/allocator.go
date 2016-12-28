// Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"fmt"
	"math"
)

type Bitmap []uint64

func (b Bitmap) Flag(i uint) {
	b[i/64] |= 1 << uint(i%64)
}

func (b Bitmap) Unflag(i uint) {
	b[i/64] &^= 1 << uint(i%64)
}

func (b Bitmap) GetFlag(i uint) bool {
	return b[i/64]&(1<<uint(i%64)) > 0
}

func minBit(b uint64) int {
	for i := 0; i < 64; i++ {
		if b&(1<<uint(i)) == 0 {
			return i
		}
	}
	return -1
}

func (b Bitmap) freeMin() int {
	for idx, i := range b {
		if i < math.MaxUint64 {
			return (idx * 64) + minBit(i)
		}
	}
	return -1
}

func NewBitmap(size int) Bitmap {
	return Bitmap(make([]uint64, (size+64-1)/64))
}

type Allocator struct {
	m        Bitmap
	min, max int
}

func NewAllocator(min, max int) *Allocator {
	return &Allocator{
		m:   NewBitmap(max - min),
		min: min,
		max: max,
	}
}

func (a *Allocator) Next() (int, error) {
	i := a.m.freeMin()
	if i < 0 || a.min+i > a.max {
		return 0, fmt.Errorf("resource full")
	}
	a.m.Flag(uint(i))
	return a.min + i, nil
}

func (a *Allocator) Release(i int) error {
	if i < a.min || i > a.max {
		return fmt.Errorf("invalid value: min: %d, max: %d", a.min, a.max)
	}
	a.m.Unflag(uint(i - a.min))
	return nil
}

func (a *Allocator) Flag(i int) error {
	if i < a.min || i > a.max {
		return fmt.Errorf("invalid value: min: %d, max: %d", a.min, a.max)
	}
	if a.m.GetFlag(uint(i - a.min)) {
		return fmt.Errorf("already used")
	}
	a.m.Flag(uint(i - a.min))
	return nil
}
