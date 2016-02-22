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
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/apex/log"
	"github.com/ishidawataru/goldp/api"
	"github.com/ishidawataru/goldp/packet"
)

type FsmState uint8

const (
	NON_EXISTENT FsmState = iota
	INITIALIZED
	OPENREC
	OPENSENT
	OPERATIONAL
)

func (s FsmState) String() string {
	switch s {
	case NON_EXISTENT:
		return "non-existent"
	case INITIALIZED:
		return "initialized"
	case OPENREC:
		return "openrec"
	case OPENSENT:
		return "opensent"
	case OPERATIONAL:
		return "operational"
	}
	return fmt.Sprintf("unknown(%d)", s)
}

type LDPSession struct {
	peerID ldp.LDPIdentifier
	dst    net.IP
	src    net.IP
	reqCh  chan *api.Request
	ConnCh chan *net.TCPConn
	conn   *net.TCPConn
	endCh  chan struct{}
}

func (s *LDPSession) Active() bool {
	return binary.BigEndian.Uint32(s.src) > binary.BigEndian.Uint32(s.dst)
}

func (s *LDPSession) tryConnect() error {
	if s.conn != nil {
		log.Debug("already have connection")
		return fmt.Errorf("aleady have connection")
	}
	interval := 1
	go func() {
		for {
			timer := time.NewTimer(time.Duration(interval) * time.Second)
			if interval < 30 {
				interval *= 2
			}
			select {
			case <-timer.C:
			case <-s.endCh:
				return
			}

			src, _ := net.ResolveTCPAddr("tcp4", fmt.Sprintf("%s:0", s.src.String()))
			dst, _ := net.ResolveTCPAddr("tcp4", fmt.Sprintf("%s:%d", s.dst.String(), ldp.TCP_PORT))
			conn, err := net.DialTCP("tcp4", src, dst)
			if err == nil {
				log.Debug("connected")
				s.ConnCh <- conn
				return
			} else {
				log.Debugf("%s", err)
			}
		}
	}()
	return nil
}

func (s *LDPSession) loop() error {
	for {
		conn := <-s.ConnCh
		s.conn = conn

		_, err := conn.Write([]byte("hello"))
		if err != nil {
			log.Errorf("%s", err)
			conn.Close()
			s.conn = nil
			s.tryConnect()
			continue
		}
		buf := make([]byte, 128)
		_, err = conn.Read(buf)
		if err != nil {
			log.Errorf("%s", err)
			conn.Close()
			s.conn = nil
			s.tryConnect()
			continue
		}
		log.Debugf("read %s", string(buf))
	}
}

func NewLDPSession(h *hello, routerId string, reqCh chan *api.Request) (*LDPSession, error) {
	ip, _, _ := net.SplitHostPort(h.from.String())
	dst := net.ParseIP(ip)
	src := net.ParseIP(routerId)

	s := &LDPSession{
		peerID: h.id,
		dst:    dst.To4(),
		src:    src.To4(),
		reqCh:  reqCh,
		ConnCh: make(chan *net.TCPConn),
		endCh:  make(chan struct{}),
	}
	if s.Active() {
		s.tryConnect()
	}
	go s.loop()
	return s, nil
}
