// Copyright 2026 Dominik Schlosser
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy

import (
	"fmt"
	"sync"
)

// Store is a thread-safe ring buffer of traffic entries with SSE broadcast support.
type Store struct {
	mu          sync.RWMutex
	entries     []*TrafficEntry
	maxSize     int
	nextID      int64
	nextFlowID  int64
	flows       map[string]string // correlation key → flow ID
	subscribers map[int64]chan *TrafficEntry
	subID       int64
}

// NewStore creates a new store with the given maximum entry count.
func NewStore(maxSize int) *Store {
	return &Store{
		maxSize:     maxSize,
		entries:     make([]*TrafficEntry, 0, maxSize),
		flows:       make(map[string]string),
		subscribers: make(map[int64]chan *TrafficEntry),
	}
}

// Add stores a traffic entry, evicting the oldest if the buffer is full,
// and notifies all SSE subscribers.
func (s *Store) Add(entry *TrafficEntry) {
	s.mu.Lock()
	s.nextID++
	entry.ID = s.nextID

	// Flow correlation
	if keys := ExtractCorrelationKeys(entry); len(keys) > 0 {
		for _, key := range keys {
			if flowID, ok := s.flows[key]; ok {
				entry.FlowID = flowID
				break
			}
		}
		if entry.FlowID == "" {
			s.nextFlowID++
			entry.FlowID = fmt.Sprintf("flow-%d", s.nextFlowID)
		}
		for _, key := range keys {
			s.flows[key] = entry.FlowID
		}
	}

	if len(s.entries) >= s.maxSize {
		evicted := s.entries[0]
		s.entries = s.entries[1:]
		// Drop the evicted entry's correlation keys so flows does not grow
		// without bound over a long session. A logical flow spans a handful of
		// entries within seconds, far fewer than maxSize, so the keys removed
		// here belong to flows that are long finished.
		for _, key := range ExtractCorrelationKeys(evicted) {
			delete(s.flows, key)
		}
	}
	s.entries = append(s.entries, entry)
	// Snapshot subscribers under lock
	subs := make([]chan *TrafficEntry, 0, len(s.subscribers))
	for _, ch := range s.subscribers {
		subs = append(subs, ch)
	}
	s.mu.Unlock()

	// Notify outside of lock to avoid blocking
	for _, ch := range subs {
		select {
		case ch <- entry:
		default:
			// subscriber too slow, skip
		}
	}
}

// Entries returns a snapshot of all stored entries.
func (s *Store) Entries() []*TrafficEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*TrafficEntry, len(s.entries))
	copy(out, s.entries)
	return out
}

// FlowEntries returns all entries belonging to the given flow.
func (s *Store) FlowEntries(flowID string) []*TrafficEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*TrafficEntry
	for _, e := range s.entries {
		if e.FlowID == flowID {
			out = append(out, e)
		}
	}
	return out
}

// SubscriberCount returns the number of active SSE subscribers.
func (s *Store) SubscriberCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.subscribers)
}

// Subscribe returns a channel that receives new traffic entries and an unsubscribe function.
func (s *Store) Subscribe() (<-chan *TrafficEntry, func()) {
	ch := make(chan *TrafficEntry, 64)
	s.mu.Lock()
	s.subID++
	id := s.subID
	s.subscribers[id] = ch
	s.mu.Unlock()

	unsub := func() {
		s.mu.Lock()
		delete(s.subscribers, id)
		s.mu.Unlock()
		// Drain any buffered entries (non-blocking)
		for {
			select {
			case _, ok := <-ch:
				if !ok {
					return
				}
			default:
				return
			}
		}
	}
	return ch, unsub
}
