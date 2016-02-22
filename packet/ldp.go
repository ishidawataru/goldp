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

package ldp

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
)

var VERSION = uint16(1)

var UDP_PORT = 646
var TCP_PORT = 646

var IMP_NULL_LABEL = 3

var HEADER_SIZE = 10

type TLVType uint16

const (
	TLV_TYPE_FEC                       TLVType = 0x0100
	TLV_TYPE_ADDRESS_LIST                      = 0x0101
	TLV_TYPE_HOP_COUNT                         = 0x0103
	TLV_TYPE_PATH_VECTOR                       = 0x0104
	TLV_TYPE_GENERIC                           = 0x0200
	TLV_TYPE_ATM                               = 0x0201
	TLV_TYPE_FRAME_RELAY                       = 0x0202
	TLV_TYPE_STATUS                            = 0x0300
	TLV_TYPE_EXTENDED_STATUS                   = 0x0301 // Notification Message
	TLV_TYPE_RETURNED_PDU                      = 0x0302 // Notification Message
	TLV_TYPE_RETURNED_MSG                      = 0x0303 // Notification Message
	TLV_TYPE_COMMON_HELLO_PARAM                = 0x0400 // Hello Message
	TLV_TYPE_IPV4_TRANSPORT_ADDRESS            = 0x0401 // Hello Message
	TLV_TYPE_CONFIG_SEQ_NUM                    = 0x0402 // Hello Message
	TLV_TYPE_IPV6_TRANSPORT_ADDRESS            = 0x0403 // Hello Message
	TLV_TYPE_COMMON_SESSION_PARAM              = 0x0500 // Init Message
	TLV_TYPE_ATM_SESSION_PARAM                 = 0x0501 // Init Message
	TLV_TYPE_FRAME_RELAY_SESSION_PARAM         = 0x0502 // Init Message
	TLV_TYPE_LABEL_REQ_MSG_ID                  = 0x0600 // Label Mapping Message
	// 0x3E00 - 0x3EFF LDP Vendor-Private Extensions
	// 0x3F00 - 0x3FFF LDP Experimental Extensions
)

func parseTLV(buf []byte) (TLVInterface, []byte, error) {
	if len(buf) < 4 {
		return nil, nil, fmt.Errorf("failed to parse TLV lack of bytes. needs 4 at least but got %d", len(buf))
	}
	t := binary.BigEndian.Uint16(buf[:2])
	//	ubit := (t & (1 << 15)) > 0
	//	fbit := (t & (1 << 14)) > 0
	typ := TLVType(t &^ (1<<15 | 1<<14))
	l := binary.BigEndian.Uint16(buf[2:])
	if len(buf) < int(4+l) {
		return nil, nil, fmt.Errorf("failed to parse TLV(%s) lack of bytes. needs %d but got %d", typ, 4+l, len(buf))
	}
	var tlv TLVInterface
	switch typ {
	case TLV_TYPE_COMMON_HELLO_PARAM:
		tlv = &CommonHelloParamTLV{}
	default:
		return nil, nil, fmt.Errorf("unknown tlv type %s", typ)
	}
	return tlv, buf[4+l:], tlv.Decode(buf[4 : 4+l])
}

func serializeTLV(typ TLVType, value []byte) ([]byte, error) {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint16(hdr, uint16(typ))
	binary.BigEndian.PutUint16(hdr[2:], uint16(len(value)))
	return append(hdr, value...), nil
}

type TLVInterface interface {
	Decode([]byte) error
	Serialize() ([]byte, error)
	Type() TLVType
	String() string
	MarshalJSON() ([]byte, error)
}

type CommonHelloParamTLV struct {
	HoldTime uint16
	T        bool // Targeted Hello
	R        bool // Request Send Targeted Hellos
}

func (t *CommonHelloParamTLV) Decode(data []byte) error {
	if len(data) != 4 {
		return fmt.Errorf("invalid value length. expects 4 not %d", len(data))
	}
	t.HoldTime = binary.BigEndian.Uint16(data[:2])
	if (data[2] & (1 << 7)) > 0 {
		t.T = true
	}
	if (data[2] & (1 << 6)) > 0 {
		t.R = true
	}
	return nil
}

func (t *CommonHelloParamTLV) Serialize() ([]byte, error) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf, t.HoldTime)
	bits := uint16(0)
	if t.T {
		bits |= 1 << 15
	}
	if t.R {
		bits |= 1 << 14
	}
	binary.BigEndian.PutUint16(buf[2:], bits)
	return serializeTLV(t.Type(), buf)
}

func (t *CommonHelloParamTLV) Type() TLVType {
	return TLV_TYPE_COMMON_HELLO_PARAM
}

func (t *CommonHelloParamTLV) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 16))
	buf.WriteString(fmt.Sprintf("[ HELLO | hold-time: %d", t.HoldTime))
	if t.T {
		buf.WriteString(", targeted")
	}
	if t.R {
		buf.WriteString(", request")
	}
	buf.WriteString(" ]")
	return buf.String()
}

func (t *CommonHelloParamTLV) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		typ      TLVType `json:"type"`
		holdtime uint16  `json:"holdtime"`
		targeted bool    `json:"targeted"`
		request  bool    `json:"request"`
	}{
		typ:      MSG_TYPE_HELLO,
		holdtime: t.HoldTime,
		targeted: t.T,
		request:  t.R,
	})
}

func NewCommonHelloParamTLV(holdtime uint16, targeted, request bool) *CommonHelloParamTLV {
	return &CommonHelloParamTLV{
		HoldTime: holdtime,
		T:        targeted,
		R:        request,
	}
}

type MessageType uint16

const (
	MSG_TYPE_NOTIFICATION        MessageType = 0x0001
	MSG_TYPE_HELLO                           = 0x0100
	MSG_TYPE_INIT                            = 0x0200
	MSG_TYPE_KEEPALIVE                       = 0x0201
	MSG_TYPE_ADDRESS                         = 0x0300
	MSG_TYPE_ADDRESS_WITHDRAW                = 0x0301
	MSG_TYPE_LABEL_MAPPING                   = 0x0400
	MSG_TYPE_LABEL_REQUEST                   = 0x0401
	MSG_TYPE_LABEL_ABORT_REQUEST             = 0x0404
	MSG_TYPE_LABEL_WITHDRAW                  = 0x0402
	MSG_TYPE_LABEL_RELEASE                   = 0x0403
	// 0x3E00 - 0x3EFF LDP Vendor-Private Extensions
	// 0x3F00 - 0x3FFF LDP Experimental Extensions
)

func (t MessageType) String() string {
	switch t {
	case MSG_TYPE_NOTIFICATION:
		return "notification"
	case MSG_TYPE_HELLO:
		return "hello"
	case MSG_TYPE_INIT:
		return "init"
	case MSG_TYPE_KEEPALIVE:
		return "keepalive"
	case MSG_TYPE_ADDRESS:
		return "address"
	case MSG_TYPE_ADDRESS_WITHDRAW:
		return "address-withdraw"
	case MSG_TYPE_LABEL_MAPPING:
		return "label-mapping"
	case MSG_TYPE_LABEL_REQUEST:
		return "label-request"
	case MSG_TYPE_LABEL_ABORT_REQUEST:
		return "label-abort-request"
	case MSG_TYPE_LABEL_WITHDRAW:
		return "label-withdraw"
	case MSG_TYPE_LABEL_RELEASE:
		return "label-release"
	}
	return fmt.Sprintf("unknown msg(%d)", t)
}

func ParseMessage(buf []byte) (MessageInterface, []byte, error) {
	if len(buf) < 8 {
		return nil, nil, fmt.Errorf("failed to parse msg, lack of bytes, needs 8 at least but got %d", len(buf))
	}
	t := binary.BigEndian.Uint16(buf[:2])
	// ubit := (t & (1 << 15)) > 0
	typ := MessageType(t &^ (1 << 15))
	l := binary.BigEndian.Uint16(buf[2:4])
	if len(buf) < int(4+l) {
		return nil, nil, fmt.Errorf("failed to parse msg(%s) lack of bytes. needs %d but got %d", typ, 4+l, len(buf))
	}
	id := binary.BigEndian.Uint32(buf[4:8])
	var msg MessageInterface
	switch typ {
	case MSG_TYPE_HELLO:
		msg = &HelloMessage{}
	default:
		return nil, nil, fmt.Errorf("unknown msg type %s", typ)
	}
	msg.SetMsgId(id)
	return msg, buf[4+l:], msg.Decode(buf[4 : 4+l])
}

func serializeMessage(typ MessageType, id uint32, value []byte) ([]byte, error) {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint16(buf, uint16(typ))
	binary.BigEndian.PutUint16(buf[2:], uint16(4+len(value)))
	binary.BigEndian.PutUint32(buf[4:], id)
	return append(buf, value...), nil
}

type MessageInterface interface {
	Decode(data []byte) error
	Serialize() ([]byte, error)
	Type() MessageType
	SetMsgId(uint32)
	MsgId() uint32
}

type HelloMessage struct {
	id               uint32
	CommonHelloParam *CommonHelloParamTLV
	OptionalTLVs     []TLVInterface
}

func (m *HelloMessage) Decode(data []byte) error {
	if len(data) < 12 {
		return fmt.Errorf("failed to parse msg(%s) lack of bytes. needs 12 at least %d", m.Type(), len(data))
	}
	m.id = binary.BigEndian.Uint32(data[:4])
	tlv, rest, err := parseTLV(data[4:])
	if err != nil {
		return err
	}

	if tlv.Type() != TLV_TYPE_COMMON_HELLO_PARAM {
		return fmt.Errorf("invalid tlv type. expect %s but got %s", TLV_TYPE_COMMON_HELLO_PARAM, tlv.Type())
	}
	m.CommonHelloParam = tlv.(*CommonHelloParamTLV)

	data = rest

	for len(data) > 0 {
		tlv, rest, err = parseTLV(data)
		if err != nil {
			return err
		}
		if m.OptionalTLVs == nil {
			m.OptionalTLVs = []TLVInterface{}
		}
		m.OptionalTLVs = append(m.OptionalTLVs, tlv)
		data = rest
	}
	return nil
}

func (m *HelloMessage) Serialize() ([]byte, error) {
	buf, err := m.CommonHelloParam.Serialize()
	if err != nil {
		return nil, err
	}
	for _, o := range m.OptionalTLVs {
		bbuf, err := o.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, bbuf...)
	}
	return serializeMessage(m.Type(), m.id, buf)
}

func (m *HelloMessage) Type() MessageType {
	return MSG_TYPE_HELLO
}

func (m *HelloMessage) MsgId() uint32 {
	return m.id
}

func (m *HelloMessage) SetMsgId(id uint32) {
	m.id = id
}

func NewHelloMessage(id uint32, param *CommonHelloParamTLV, optionals []TLVInterface) *HelloMessage {
	return &HelloMessage{
		id:               id,
		CommonHelloParam: param,
		OptionalTLVs:     optionals,
	}
}

type LDPIdentifier []byte

func (lhs LDPIdentifier) Equal(rhs LDPIdentifier) bool {
	return bytes.Equal([]byte(lhs), []byte(rhs))
}

func (i LDPIdentifier) String() string {
	return fmt.Sprintf("%s:%d", net.IP([]byte(i)[:4]).String(), i[4])
}

func NewLDPIdentifier(s string) (LDPIdentifier, error) {
	var id LDPIdentifier
	host, space, err := net.SplitHostPort(s)
	if err != nil {
		return id, err
	}
	fst := net.ParseIP(host)
	if fst.To4() == nil {
		return id, fmt.Errorf("invalid LDP router ID: %s", fst)
	}
	snd, err := strconv.Atoi(space)
	if err != nil {
		return id, fmt.Errorf("invalid local label space ID")
	}
	buf := []byte(fst.To4())
	buf = append(buf, make([]byte, 2)...)
	binary.BigEndian.PutUint16(buf[4:], uint16(snd))
	return LDPIdentifier(buf), nil
}

type Header struct {
	Version       uint16
	Length        uint16 // length excluding version and length fields
	LDPIdentifier LDPIdentifier
}

func ParseHeader(buf []byte) (*Header, error) {
	if len(buf) < HEADER_SIZE {
		return nil, fmt.Errorf("failed to parse header, lack of bytes. needs %d but got %d", HEADER_SIZE, len(buf))
	}
	version := binary.BigEndian.Uint16(buf[:2])
	if version != VERSION {
		return nil, fmt.Errorf("failed to parse header, invalid version. expect %d got %d", VERSION, version)
	}
	length := binary.BigEndian.Uint16(buf[2:4])
	return &Header{
		Version:       version,
		Length:        length,
		LDPIdentifier: LDPIdentifier(buf[4:HEADER_SIZE]),
	}, nil
}

type PDU struct {
	Header   *Header
	Messages []MessageInterface
}

func (p *PDU) Serialize() ([]byte, error) {
	if len(p.Messages) < 0 {
		return nil, fmt.Errorf("PDU has no message")
	}
	buf, err := p.Messages[0].Serialize()
	if err != nil {
		return nil, err
	}
	for _, msg := range p.Messages[1:] {
		b, err := msg.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, b...)
	}
	hdr := make([]byte, HEADER_SIZE)
	binary.BigEndian.PutUint16(hdr[:2], uint16(p.Header.Version))
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(buf)+6))
	copy(hdr[4:HEADER_SIZE], p.Header.LDPIdentifier)
	return append(hdr, buf...), nil
}

func NewPDU(id LDPIdentifier, msgs ...MessageInterface) *PDU {
	return &PDU{
		Header: &Header{
			Version:       VERSION,
			LDPIdentifier: id,
		},
		Messages: msgs,
	}
}
