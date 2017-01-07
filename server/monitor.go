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
	"sync"
)

type EventType uint64

const (
	EVENT_SESSION_ADD EventType = 1 << iota
	EVENT_SESSION_DEL
	EVENT_SESSION_UPDATE
	EVENT_LABEL_LOCAL_ADD
	EVENT_LABEL_LOCAL_DEL

	EVENT_SESSION     EventType = EVENT_SESSION_ADD | EVENT_SESSION_DEL | EVENT_SESSION_UPDATE
	EVENT_LABEL_LOCAL EventType = EVENT_LABEL_LOCAL_ADD | EVENT_LABEL_LOCAL_DEL
	EVENT_LABEL       EventType = EVENT_LABEL_LOCAL
)

func (t EventType) String() string {
	switch t {
	case EVENT_SESSION_ADD:
		return "SESSION_ADD"
	case EVENT_SESSION_DEL:
		return "SESSION_DEL"
	case EVENT_SESSION_UPDATE:
		return "SESSION_UPDATE"
	case EVENT_LABEL_LOCAL_ADD:
		return "LABEL_LOCAL_ADD"
	case EVENT_LABEL_LOCAL_DEL:
		return "LABEL_LOCAL_DEL"
	}
	return fmt.Sprintf("unknownEvent(%d)", t)
}

type Event struct {
	Type EventType
	Data interface{}
}

type Watcher interface {
	Stop()
	Next() *Event
	emit(*Event) bool
	ch() <-chan *Event
}

type SyncWatcher struct {
	t   EventType
	c   chan *Event
	end chan struct{}
}

func (w *SyncWatcher) Stop() {
	close(w.end)
}

func (w *SyncWatcher) Next() *Event {
	select {
	case e := <-w.c:
		return e
	case <-w.end:
		return nil
	}
}

func (w *SyncWatcher) emit(ev *Event) bool {
	if w.t&ev.Type > 0 {
		select {
		case w.c <- ev:
		case <-w.end:
			return false
		}
	}
	return true
}

func (w *SyncWatcher) ch() <-chan *Event {
	return w.c
}

func newSyncWatcher(t EventType) Watcher {
	return &SyncWatcher{
		t:   t,
		c:   make(chan *Event),
		end: make(chan struct{}),
	}
}

type monitorServer struct {
	m  sync.RWMutex
	ws []Watcher
}

func (s *monitorServer) emit(t EventType, data interface{}) error {
	s.m.Lock()
	defer s.m.Unlock()
	ws := make([]Watcher, 0, len(s.ws))
	ev := &Event{
		Type: t,
		Data: data,
	}
	for _, w := range s.ws {
		if w.emit(ev) {
			ws = append(ws, w)
		}
	}
	s.ws = ws
	return nil
}

func (s *monitorServer) monitor(t EventType) (Watcher, error) {
	s.m.Lock()
	defer s.m.Unlock()
	w := newSyncWatcher(t)
	s.ws = append(s.ws, w)
	return w, nil
}

func newMonitorServer() *monitorServer {
	return &monitorServer{
		ws: make([]Watcher, 0),
	}
}
