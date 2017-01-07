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
	"github.com/ishidawataru/goldp/config"
	"github.com/ishidawataru/goldp/packet"
	"gopkg.in/tomb.v2"
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

type fsmState uint8

const (
	NON_EXISTENT fsmState = iota
	INITIALIZED
	OPENREC
	OPENSENT
	OPERATIONAL
)

func (s fsmState) String() string {
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
	t               tomb.Tomb
	readT           tomb.Tomb
	s               *Server
	localID         ldp.LDPIdentifier
	peerID          ldp.LDPIdentifier
	dst             net.IP
	src             net.IP
	ConnCh          chan *net.TCPConn
	conn            *net.TCPConn
	msgCh           chan ldp.MessageInterface
	errCh           chan error
	state           fsmState
	gConf           config.Global
	sConf           config.Session
	peerInitMsg     *ldp.InitMessage
	localInitMsg    *ldp.InitMessage
	labelWatcher    Watcher
	ifindex         int
	connectInterval int
}

func (s *LDPSession) Active() bool {
	return binary.BigEndian.Uint32(s.src) > binary.BigEndian.Uint32(s.dst)
}

func (s *LDPSession) tryConnect() error {
	if s.conn != nil {
		log.Debug("already have connection")
		return fmt.Errorf("aleady have connection")
	}
	if s.connectInterval < 1 {
		s.connectInterval = 1
	} else if s.connectInterval < 30 {
		s.connectInterval *= 2
	}
	log.Debugf("try connect (sleep %d sec)", s.connectInterval)
	s.t.Go(func() error {
		for {
			timer := time.NewTimer(time.Duration(s.connectInterval) * time.Second)
			select {
			case <-timer.C:
			case <-s.t.Dying():
				log.Debug("try connect dying")
				return nil
			}

			src, _ := net.ResolveTCPAddr("tcp4", fmt.Sprintf("%s:0", s.src.String()))
			dst, _ := net.ResolveTCPAddr("tcp4", fmt.Sprintf("%s:%d", s.dst.String(), ldp.TCP_PORT))
			conn, err := net.DialTCP("tcp4", src, dst)
			if err == nil {
				log.Debug("connected")
				s.ConnCh <- conn
				return nil
			} else {
				log.Debugf("%s", err)
			}

			if s.connectInterval < 30 {
				s.connectInterval *= 2
			}
			log.Debugf("try connect (sleep %d sec)", s.connectInterval)
		}
	})
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

func (s *LDPSession) read() error {
	for {
		buf, err := readAll(s.conn, ldp.HEADER_SIZE)
		if err != nil {
			select {
			case s.errCh <- err:
			case <-s.t.Dying():
			}
			return nil
		}
		hdr, err := ldp.ParseHeader(buf)
		if err != nil {
			select {
			case s.errCh <- err:
			case <-s.t.Dying():
			}
			return nil
		}
		// hdr.Length includes the length of LDPIdentifier(len: 6)
		// which is contained in ldp header
		buf, err = readAll(s.conn, int(hdr.Length)-6)
		if err != nil {
			select {
			case s.errCh <- err:
			case <-s.t.Dying():
			}
			return nil
		}
		for len(buf) > 0 {
			msg, rest, err := ldp.ParseMessage(buf)
			if err != nil {
				select {
				case s.errCh <- err:
				case <-s.t.Dying():
				}
				return nil
			}
			select {
			case s.msgCh <- msg:
			case <-s.t.Dying():
				return nil
			}
			buf = rest
		}
	}
}

func (s *LDPSession) write(msgs ...ldp.MessageInterface) error {
	if len(msgs) == 0 {
		return nil
	}
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

// one session could contain multiple interfaces
func buildAddrMsg(c []config.Interface) []ldp.MessageInterface {
	ipv4 := make([]net.IP, 0, len(c))
	ipv6 := make([]net.IP, 0, len(c))
	for _, i := range c {
		for _, a := range i.Addresses {
			ip := net.ParseIP(a)
			if ip.To4() != nil {
				ipv4 = append(ipv4, ip)
			} else {
				ipv6 = append(ipv6, ip)
			}
		}
	}
	log.Infof("ipv4: %v, ipv6: %v", ipv4, ipv6)
	msgs := make([]ldp.MessageInterface, 0, 2)
	if len(ipv4) > 0 {
		msgs = append(msgs, &ldp.AddressMessage{
			List: &ldp.AddressListTLV{
				Family: ldp.AFI_IP,
				List:   ipv4,
			},
		})
	}
	if len(ipv6) > 0 {
		msgs = append(msgs, &ldp.AddressMessage{
			List: &ldp.AddressListTLV{
				Family: ldp.AFI_IP6,
				List:   ipv6,
			},
		})
	}
	return msgs
}

func buildLabelMappingMsg(c ...config.Mapping) []ldp.MessageInterface {
	msgs := make([]ldp.MessageInterface, 0, len(c))
	for _, m := range c {
		_, prefix, err := net.ParseCIDR(m.Prefix)
		if err != nil {
			return nil
		}
		fecTLV := &ldp.FECTLV{
			Elements: []*ldp.FECElement{
				&ldp.FECElement{
					Type:   ldp.FEC_PREFIX,
					Family: ldp.AFI_IP,
					Prefix: prefix,
				},
			},
		}
		labelTLV := &ldp.LabelTLV{
			Label: m.Local,
		}
		msgs = append(msgs, &ldp.LabelMappingMessage{
			FEC:   fecTLV,
			Label: labelTLV,
		})
	}
	return msgs
}

func buildLabelWithdrawMsg(c ...config.Mapping) []ldp.MessageInterface {
	msgs := make([]ldp.MessageInterface, 0, len(c))
	for _, m := range c {
		_, prefix, err := net.ParseCIDR(m.Prefix)
		if err != nil {
			return nil
		}
		fecTLV := &ldp.FECTLV{
			Elements: []*ldp.FECElement{
				&ldp.FECElement{
					Type:   ldp.FEC_PREFIX,
					Family: ldp.AFI_IP,
					Prefix: prefix,
				},
			},
		}
		msgs = append(msgs, &ldp.LabelWithdrawMessage{
			FEC: fecTLV,
		})
	}
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

func (s *LDPSession) sendMapping(label int, fec ...string) error {
	return nil
}

func (s *LDPSession) handleMsg(msg ldp.MessageInterface) error {
	switch msg.Type() {
	case ldp.MSG_TYPE_KEEPALIVE:
	case ldp.MSG_TYPE_ADDRESS:
		m := msg.(*ldp.AddressMessage)
		addrs := make([]string, 0, len(m.List.List))
		for _, a := range m.List.List {
			addrs = append(addrs, a.String())
		}
		return s.s.addNexthop(s.peerID, addrs...)
	case ldp.MSG_TYPE_ADDRESS_WITHDRAW:
		m := msg.(*ldp.AddressWithdrawMessage)
		addrs := make([]string, 0, len(m.List.List))
		for _, a := range m.List.List {
			addrs = append(addrs, a.String())
		}
		return s.s.delNexthop(s.peerID, addrs...)
	case ldp.MSG_TYPE_LABEL_MAPPING:
		m := msg.(*ldp.LabelMappingMessage)
		prefix := make([]string, 0, len(m.FEC.Elements))
		for _, a := range m.FEC.Elements {
			prefix = append(prefix, a.Prefix.String())
		}
		label := m.Label.Label
		// TODO msg id handling
		return s.s.addRemoteLabelMapping(s.peerID, label, prefix...)
	case ldp.MSG_TYPE_LABEL_REQUEST:
		m := msg.(*ldp.LabelRequestMessage)
		addrs := make([]string, 0, len(m.FEC.Elements))
		for _, a := range m.FEC.Elements {
			addrs = append(addrs, a.Prefix.String())
		}
		// TODO msg id handling
		return s.s.requestMapping(s.peerID, addrs...)
	case ldp.MSG_TYPE_LABEL_WITHDRAW:
		//		if len(m.FEC.Elements) == 1 && m.FEC.Elements[0].Type == ldp.FEC_WILDCARD {
		//		    return s.s.
		//		}
		m := msg.(*ldp.LabelWithdrawMessage)
		prefix := make([]string, 0, len(m.FEC.Elements))
		for _, a := range m.FEC.Elements {
			prefix = append(prefix, a.Prefix.String())
		}
		label := 0
		if m.Label != nil {
			label = m.Label.Label
		}
		// TODO msg id handling
		return s.s.delRemoteLabelMapping(s.peerID, label, prefix...)
	}
	return nil
}

func (s *LDPSession) monitorLocalLabel() error {
	w, err := s.s.monitorServer.monitor(EVENT_LABEL_LOCAL)
	if err != nil {
		return err
	}
	s.labelWatcher = w
	go func() error {
		for {
			e := w.Next()
			if e == nil {
				return nil
			}
			d := e.Data.(config.Mapping)
			switch e.Type {
			case EVENT_LABEL_LOCAL_ADD:
				if err := s.write(buildLabelMappingMsg(d)...); err != nil {
					return err
				}
			case EVENT_LABEL_LOCAL_DEL:
				if err := s.write(buildLabelWithdrawMsg(d)...); err != nil {
					return err
				}
			}
		}
	}()
	return nil
}

func (s *LDPSession) stopMonitorLocalLabel() {
	if s.labelWatcher != nil {
		s.labelWatcher.Stop()
	}
}

func (s *LDPSession) loop() error {
	for {
		cur := s.state
		log.Debugf("loop: %s", cur)
		next := NON_EXISTENT
		switch cur {
		case NON_EXISTENT:
			if s.conn != nil {
				s.conn.Close()
				s.readT.Kill(nil)
				s.readT.Wait()
				s.readT = tomb.Tomb{}
				s.conn = nil
			}
			if s.Active() {
				s.tryConnect()
			}
			select {
			case s.conn = <-s.ConnCh:
			case <-s.t.Dying():
				log.Debug("loop() dying")
				return nil
			}
			s.readT.Go(s.read)
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
				case <-s.t.Dying():
					s.conn.Close()
					log.Debug("loop() dying")
					return nil
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
			case <-s.t.Dying():
				s.conn.Close()
				log.Debug("loop() dying")
				return nil
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
			case <-s.t.Dying():
				s.conn.Close()
				log.Debug("loop() dying")
				return nil
			}
		case OPERATIONAL:
			s.connectInterval = 0
			d := time.Second * time.Duration(s.sConf.KeepAliveTime)
			k := time.NewTicker(d)
			h := time.NewTimer(d * 3)

			i, err := s.s.GetInterface(config.Interface{Index: s.ifindex})
			if err != nil {
				next = NON_EXISTENT
				break
			}

			if err := s.write(buildAddrMsg([]config.Interface{i})...); err != nil {
				log.Warnf("failed to write address messages: %s", err)
				next = NON_EXISTENT
				break
			}

			for {
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
						if err := s.handleMsg(msg); err != nil {
							log.Warnf("err: %s", err)
							next = NON_EXISTENT
						} else {
							h.Reset(d * 3)
							next = OPERATIONAL
						}
					}
					//				case msg := <-monCh:
					//					log.Debugf("mon: %s", msg)
				case err := <-s.errCh:
					log.Warnf("%s", err)
					next = NON_EXISTENT
				case <-s.t.Dying():
					s.conn.Close()
					log.Debug("loop() dying")
					return nil
				}

				if next != OPERATIONAL {
					break
				}
			}
		}

		log.Infof("fsm %s state transition: %s -> %s", s.peerID, cur, next)
		s.sConf.PrevFSMState = cur.String()
		s.sConf.FSMState = next.String()
		s.s.monitorServer.emit(EVENT_SESSION_UPDATE, s.ToConfig())
		s.state = next
	}
}

func (s *LDPSession) ToConfig() config.Session {
	return s.sConf
}

func (s *LDPSession) stop() {
	s.t.Kill(nil)
	s.t.Wait()
	if s.conn != nil {
		s.conn.Close()
		s.readT.Kill(nil)
		s.readT.Wait()
	}
	s.sConf.PrevFSMState = s.sConf.FSMState
	s.sConf.FSMState = NON_EXISTENT.String()
	go func() {
		s.s.monitorServer.emit(EVENT_SESSION_UPDATE, s.ToConfig())
	}()
}

func newLDPSession(h *hello, server *Server) (*LDPSession, error) {
	conf := server.config
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
		ConnCh:  make(chan *net.TCPConn),
		msgCh:   make(chan ldp.MessageInterface),
		errCh:   make(chan error),
		state:   NON_EXISTENT,
		gConf:   conf.Global,
		sConf:   sConf,
		ifindex: h.ifindex,
		s:       server,
	}
	s.t.Go(s.loop)
	return s, nil
}
