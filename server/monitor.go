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
	"sync"
)

type EventType uint64

const (
	EVENT_SESSION_ADD EventType = 1 << iota
	EVENT_SESSION_DEL
	EVENT_SESSION_UPDATE

	EVENT_SESSION EventType = EVENT_SESSION_ADD | EVENT_SESSION_DEL | EVENT_SESSION_UPDATE
)

type Event struct {
	Type EventType
	Data interface{}
}

type Watcher struct {
	t   EventType
	ch  chan *Event
	end chan struct{}
}

func (w *Watcher) Stop() {
	close(w.end)
}

func (w *Watcher) Next() *Event {
	select {
	case e := <-w.ch:
		return e
	case <-w.end:
		return nil
	}
}

func newWatcher(t EventType) *Watcher {
	return &Watcher{
		t:   t,
		ch:  make(chan *Event),
		end: make(chan struct{}),
	}
}

type monitorServer struct {
	m  sync.RWMutex
	ws []*Watcher
}

func (s *monitorServer) emit(t EventType, data interface{}) error {
	s.m.Lock()
	defer s.m.Unlock()
	ws := make([]*Watcher, 0, len(s.ws))
	for _, w := range s.ws {
		if w.t&t > 0 {
			select {
			case w.ch <- &Event{
				Type: t,
				Data: data,
			}:
				ws = append(ws, w)
			case <-w.end:
			}
		} else {
			ws = append(ws, w)
		}
	}
	s.ws = ws
	return nil
}

func (s *monitorServer) monitor(t EventType) (*Watcher, error) {
	s.m.Lock()
	defer s.m.Unlock()
	w := newWatcher(t)
	s.ws = append(s.ws, w)
	return w, nil
}

func newMonitorServer() *monitorServer {
	return &monitorServer{
		ws: make([]*Watcher, 0),
	}
}
