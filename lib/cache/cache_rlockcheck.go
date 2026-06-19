//go:build cache_rlockcheck

// Teleport
// Copyright (C) 2026 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cache

import (
	"bytes"
	"fmt"
	"runtime"
	"strconv"
	"sync"
)

var rLockChecking bool

var activeRLocks sync.Map

type activeRLocksItem struct {
	mu   *rwMutex
	goid uint64
}

func enableRLockCheck() {
	rLockChecking = true
}

func finalRLockCheck() {
	activeRLocks.Range(func(key, value any) bool {
		i := key.(activeRLocksItem)
		panic(fmt.Sprintf("cache RWMutex at %p left RLocked by goroutine %d", i.mu, i.goid))
	})
}

type rwMutex struct {
	mu sync.RWMutex
}

func rwcheckGoid() uint64 {
	buf := make([]byte, 64)
	buf = buf[:runtime.Stack(buf, false)]
	buf, found := bytes.CutPrefix(buf, []byte("goroutine "))
	if !found {
		panic("could not find goroutine id from stack dump")
	}
	buf, _, found = bytes.Cut(buf, []byte(" ["))
	if !found {
		panic("could not find goroutine id from stack dump")
	}
	goid, err := strconv.ParseUint(string(buf), 10, 64)
	if err != nil {
		panic(err)
	}
	return goid
}

func (mu *rwMutex) RLock() {
	if rLockChecking {
		goid := rwcheckGoid()
		_, alreadyPresent := activeRLocks.LoadOrStore(activeRLocksItem{mu: mu, goid: goid}, nil)
		if alreadyPresent {
			panic(fmt.Sprintf("goroutine %d attempting to RLock the RWMutex at %p twice", goid, mu))
		}
	}
	mu.mu.RLock()
}
func (mu *rwMutex) RUnlock() {
	if rLockChecking {
		goid := rwcheckGoid()
		_, deleted := activeRLocks.LoadAndDelete(activeRLocksItem{mu: mu, goid: goid})
		if !deleted {
			panic(fmt.Sprintf("goroutine %d attempting to RUnlock the RWMutex at %p without holding the RLock", goid, mu))
		}
	}
	mu.mu.RUnlock()
}

func (mu *rwMutex) Lock() {
	mu.mu.Lock()
}
func (mu *rwMutex) Unlock() {
	mu.mu.Unlock()
}
