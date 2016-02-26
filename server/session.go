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
	"io"
	"net"
	"time"

	"github.com/apex/log"
	"github.com/ishidawataru/goldp/api"
	"github.com/ishidawataru/goldp/config"
	"github.com/ishidawataru/goldp/packet"
)

// RFC5036 2.5.4. Initialization State Machine
//
//              Session Initialization State Transition Diagram
//
//                              +------------+
//                              |            |
//                +------------>|NON EXISTENT|<--------------------+
//                |             |            |                     |
//                |             +------------+                     |
//                | Session        |    ^                          |
//                |   connection   |    |                          |
//                |   established  |    | Rx any LDP msg except    |
//                |                V    |   Init msg or Timeout    |
//                |            +-----------+                       |
//   Rx Any other |            |           |                       |
//      msg or    |            |INITIALIZED|                       |
//      Timeout / |        +---|           |-+                     |
//   Tx NAK msg   |        |   +-----------+ |                     |
//                |        | (Passive Role)  | (Active Role)       |
//                |        | Rx Acceptable   | Tx Init msg         |
//                |        |    Init msg /   |                     |
//                |        | Tx Init msg     |                     |
//                |        |    Tx KeepAlive |                     |
//                |        V    msg          V                     |
//                |   +-------+        +--------+                  |
//                |   |       |        |        |                  |
//                +---|OPENREC|        |OPENSENT|----------------->|
//                +---|       |        |        | Rx Any other msg |
//                |   +-------+        +--------+    or Timeout    |
//   Rx KeepAlive |        ^                |     Tx NAK msg       |
//      msg       |        |                |                      |
//                |        |                | Rx Acceptable        |
//                |        |                |    Init msg /        |
//                |        +----------------+ Tx KeepAlive msg     |
//                |                                                |
//                |      +-----------+                             |
//                +----->|           |                             |
//                       |OPERATIONAL|                             |
//                       |           |---------------------------->+
//                       +-----------+     Rx Shutdown msg
//                All other  |   ^            or Timeout /
//                  LDP msgs |   |         Tx Shutdown msg
//                           |   |
//                           +---+

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
	localID      ldp.LDPIdentifier
	peerID       ldp.LDPIdentifier
	dst          net.IP
	src          net.IP
	reqCh        chan *api.Request
	ConnCh       chan *net.TCPConn
	conn         *net.TCPConn
	endCh        chan struct{}
	msgCh        chan ldp.MessageInterface
	errCh        chan error
	state        FsmState
	reading      bool
	gConf        config.Global
	sConf        config.Session
	peerInitMsg  *ldp.InitMessage
	localInitMsg *ldp.InitMessage
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

func readAll(conn net.Conn, length int) ([]byte, error) {
	buf := make([]byte, length)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func (s *LDPSession) read() {
	s.reading = true
	for {
		buf, err := readAll(s.conn, ldp.HEADER_SIZE)
		if err != nil {
			s.errCh <- err
			s.reading = false
			return
		}
		hdr, err := ldp.ParseHeader(buf)
		if err != nil {
			s.errCh <- err
			s.reading = false
			return
		}
		// hdr.Length includes the length of LDPIdentifier(len: 6)
		// which is contained in ldp header
		buf, err = readAll(s.conn, int(hdr.Length)-6)
		if err != nil {
			s.errCh <- err
			s.reading = false
			return
		}
		for len(buf) > 0 {
			msg, rest, err := ldp.ParseMessage(buf)
			if err != nil {
				s.errCh <- err
				s.reading = false
				return
			}
			s.msgCh <- msg
			buf = rest
		}
	}
}

func (s *LDPSession) write(msgs ...ldp.MessageInterface) error {
	pdu := ldp.NewPDU(s.localID, msgs...)
	buf, err := pdu.Serialize()
	if err != nil {
		return err
	}
	_, err = s.conn.Write(buf)
	return err
}

func (s *LDPSession) buildInitMsg() ldp.MessageInterface {
	return &ldp.InitMessage{
		CommonSessionParam: &ldp.CommonSessionParamTLV{
			ProtocolVersion:       ldp.VERSION,
			KeepAliveTime:         uint16(s.sConf.KeepAliveTime),
			A:                     s.sConf.LabelAdvMode == config.DOD,
			D:                     s.sConf.LoopDetection,
			PVLim:                 uint8(s.sConf.PVLim),
			MaxPDULength:          uint16(s.sConf.MaxPDULength),
			ReceiverLDPIdentifier: s.peerID,
		},
	}
}

func (s *LDPSession) buildAddrMsg(c []config.Interface) []ldp.MessageInterface {
	ipv4 := make([]net.IP, 0, len(c))
	ipv6 := make([]net.IP, 0, len(c))
	for _, i := range c {
		for _, a := range i.Addresses {
			ip, _, _ := net.ParseCIDR(a)
			if ip.To4() != nil {
				ipv4 = append(ipv4, ip)
			} else {
				ipv6 = append(ipv6, ip)
			}
		}
	}
	msgs := make([]ldp.MessageInterface, 0, 2)
	msgs = append(msgs, &ldp.AddressMessage{
		List: &ldp.AddressListTLV{
			Family: ldp.AFI_IP,
			List:   ipv4,
		},
	})
	msgs = append(msgs, &ldp.AddressMessage{
		List: &ldp.AddressListTLV{
			Family: ldp.AFI_IP6,
			List:   ipv6,
		},
	})
	return msgs
}

func nak(code ldp.StatusCode) ldp.MessageInterface {
	return &ldp.NotificationMessage{
		Status: &ldp.StatusTLV{
			Code: code,
		},
	}
}

func (s *LDPSession) AcceptableInit(msg ldp.MessageInterface) (ldp.MessageInterface, bool) {
	init, ok := msg.(*ldp.InitMessage)
	if !ok {
		return nak(ldp.STATUS_SHUTDOWN), false
	}
	tlv := init.CommonSessionParam
	if !tlv.ReceiverLDPIdentifier.Equal(s.localID) {
		return nak(ldp.STATUS_SESSION_REJECTED_NO_HELLO), false
	}
	if tlv.A != (s.sConf.LabelAdvMode == config.DOD) {
		return nak(ldp.STATUS_SESSION_REJECTED_ADV_MODE), false
	}
	// PVLim : The configured maximum Path Vector length.  MUST be 0 if Loop
	// Detection is disabled (D = 0).
	if !tlv.D && tlv.PVLim > 0 {
		return nak(ldp.STATUS_MALFORMED_TLV_VALUE), false
	}
	// A value of 255 or less specifies the default maximum length of 4096
	// octets.
	//
	// The receiving LSR MUST calculate the maximum PDU length for the
	// session by using the smaller of its and its peer's proposals
	// for Max PDU Length.  The default maximum PDU length applies
	// before session initialization completes
	if tlv.MaxPDULength > 255 && s.sConf.MaxPDULength > int(tlv.MaxPDULength) {
		s.sConf.MaxPDULength = int(tlv.MaxPDULength)
	}
	if s.sConf.KeepAliveTime > int(tlv.KeepAliveTime) {
		s.sConf.KeepAliveTime = int(tlv.KeepAliveTime)
	}
	s.peerInitMsg = init
	m := s.buildInitMsg()
	s.localInitMsg = m.(*ldp.InitMessage)
	return m, true
}

func (s *LDPSession) loop() error {
	for {
		cur := s.state
		next := NON_EXISTENT
		switch cur {
		case NON_EXISTENT:
			if s.conn != nil {
				s.conn.Close()
				if s.reading {
					select {
					case <-s.msgCh:
					default:
					}
					<-s.errCh
				}
				s.conn = nil
			}
			if s.Active() {
				s.tryConnect()
			}
			s.conn = <-s.ConnCh
			go s.read()
			next = INITIALIZED
		case INITIALIZED:
			if s.Active() {
				if err := s.write(s.buildInitMsg()); err != nil {
					next = NON_EXISTENT
				} else {
					next = OPENSENT
				}
			} else {
				t := time.NewTimer(time.Second * 10)
				select {
				case <-t.C:
					log.Warnf("opensent timeout")
					next = NON_EXISTENT
				case msg := <-s.msgCh:
					if msg, ok := s.AcceptableInit(msg); !ok {
						s.write(msg)
						next = NON_EXISTENT
					} else if err := s.write(msg, &ldp.KeepAliveMessage{}); err != nil {
						next = NON_EXISTENT
					} else {
						next = OPENREC
					}
				case err := <-s.errCh:
					log.Warnf("%s", err)
					next = NON_EXISTENT
				}
			}
		case OPENSENT:
			if !s.Active() {
				log.Fatal("code logic bug")
			}
			t := time.NewTimer(time.Second * 10)
			select {
			case <-t.C:
				log.Warnf("opensent timeout")
				s.write(nak(ldp.STATUS_HOLD_TIMER_EXPIRED))
				next = NON_EXISTENT
			case msg := <-s.msgCh:
				if msg, ok := s.AcceptableInit(msg); !ok {
					s.write(msg)
					next = NON_EXISTENT
				} else if err := s.write(&ldp.KeepAliveMessage{}); err != nil {
					next = NON_EXISTENT
				} else {
					next = OPENREC
				}
			case err := <-s.errCh:
				log.Warnf("%s", err)
				next = NON_EXISTENT
			}
		case OPENREC:
			t := time.NewTimer(time.Second * 10)
			select {
			case <-t.C:
				log.Warnf("openrec timeout")
				s.write(nak(ldp.STATUS_HOLD_TIMER_EXPIRED))
				next = NON_EXISTENT
			case msg := <-s.msgCh:
				if msg.Type() != ldp.MSG_TYPE_KEEPALIVE {
					s.write(nak(ldp.STATUS_MISSING_MSG_PARAM))
					next = NON_EXISTENT
				} else {
					next = OPERATIONAL
				}
			case err := <-s.errCh:
				log.Warnf("%s", err)
				next = NON_EXISTENT
			}
		case OPERATIONAL:
			d := time.Second * time.Duration(s.sConf.KeepAliveTime)
			k := time.NewTicker(d)
			h := time.NewTimer(d * 3)

			monCh := make(chan *api.Request, 8)
			endCh := make(chan struct{}, 1)
			s.reqCh <- &api.Request{
				Type:  api.MON_ADDRESS,
				MonCh: monCh,
				EndCh: endCh,
			}

			ch := make(chan *api.Response)
			s.reqCh <- &api.Request{
				Type:  api.GET_INTFS,
				ResCh: ch,
			}

			next = OPERATIONAL
			if err := s.write(s.buildAddrMsg((<-ch).Data.([]config.Interface))...); err != nil {
				log.Warnf("failed to write address messages: %s", err)
				next = NON_EXISTENT
			}

			for {
				if next != OPERATIONAL {
					endCh <- struct{}{}
					break
				}
				select {
				case <-k.C:
					if err := s.write(&ldp.KeepAliveMessage{}); err != nil {
						log.Warnf("%s", err)
						next = NON_EXISTENT
					} else {
						log.Debugf("send keepalive")
						next = OPERATIONAL
					}
				case <-h.C:
					log.Warnf("operational timeout")
					err := s.write(nak(ldp.STATUS_SHUTDOWN))
					log.Warnf("err: %s", err)
					next = NON_EXISTENT
				case msg := <-s.msgCh:
					if msg.Type() == ldp.MSG_TYPE_NOTIFICATION {
						log.Warnf("got notification")
						s.write(nak(ldp.STATUS_SHUTDOWN))
						next = NON_EXISTENT
					} else {
						log.Debugf("recv: %s", msg)
						h.Reset(d * 3)
						next = OPERATIONAL
					}
				case msg := <-monCh:
					log.Debugf("mon: %s", msg)
				case err := <-s.errCh:
					log.Warnf("%s", err)
					next = NON_EXISTENT
				}
			}
		}

		log.Infof("fsm %s state transition: %s -> %s", s.peerID, cur, next)
		s.state = next
	}
}

func NewLDPSession(h *hello, conf config.Config, reqCh chan *api.Request) (*LDPSession, error) {
	ip, _, _ := net.SplitHostPort(h.from.String())
	dst := net.ParseIP(ip)
	src := net.ParseIP(conf.Global.RouterId)

	id, err := ldp.NewLDPIdentifier(fmt.Sprintf("%s:0", conf.Global.RouterId))
	if err != nil {
		return nil, err
	}

	sConf := config.Session{
		LocalId:       id.String(),
		PeerId:        h.id.String(),
		KeepAliveTime: conf.Global.KeepAliveTime,
		MaxPDULength:  conf.Global.MaxPDULength,
		LoopDetection: conf.Global.LoopDetection,
		PVLim:         conf.Global.PVLim,
		LabelAdvMode:  conf.Global.LabelAdvMode,
	}

	s := &LDPSession{
		localID: id,
		peerID:  h.id,
		dst:     dst.To4(),
		src:     src.To4(),
		reqCh:   reqCh,
		ConnCh:  make(chan *net.TCPConn),
		endCh:   make(chan struct{}),
		msgCh:   make(chan ldp.MessageInterface),
		errCh:   make(chan error),
		state:   NON_EXISTENT,
		gConf:   conf.Global,
		sConf:   sConf,
	}
	go s.loop()
	return s, nil
}
