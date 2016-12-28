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
	"strings"
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
	TLV_TYPE_LABEL_GENERIC                     = 0x0200
	TLV_TYPE_LABEL_ATM                         = 0x0201
	TLV_TYPE_LABEL_FRAME_RELAY                 = 0x0202
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

var TLVTypeNameMap = map[TLVType]string{
	TLV_TYPE_FEC:                       "FEC",
	TLV_TYPE_ADDRESS_LIST:              "ADDRESS-LIST",
	TLV_TYPE_HOP_COUNT:                 "HOP-COUNT",
	TLV_TYPE_PATH_VECTOR:               "PATH-VECTOR",
	TLV_TYPE_LABEL_GENERIC:             "GENERIC-LABEL",
	TLV_TYPE_LABEL_ATM:                 "ATM-LABEL",
	TLV_TYPE_LABEL_FRAME_RELAY:         "FRAME-RELAY-LABEL",
	TLV_TYPE_STATUS:                    "STATUS",
	TLV_TYPE_EXTENDED_STATUS:           "EXTENDED-STATUS",
	TLV_TYPE_RETURNED_PDU:              "RETURNED-PDU",
	TLV_TYPE_RETURNED_MSG:              "RETURNED-MSG",
	TLV_TYPE_COMMON_HELLO_PARAM:        "HELLO-PARAM",
	TLV_TYPE_IPV4_TRANSPORT_ADDRESS:    "IPv4-TRANSPORT",
	TLV_TYPE_CONFIG_SEQ_NUM:            "CONFIG-SEQ-NUM",
	TLV_TYPE_IPV6_TRANSPORT_ADDRESS:    "IPv6-TRANSPORT",
	TLV_TYPE_COMMON_SESSION_PARAM:      "SESSION-PARAM",
	TLV_TYPE_ATM_SESSION_PARAM:         "ATM-SESSION-PARAM",
	TLV_TYPE_FRAME_RELAY_SESSION_PARAM: "FRAME-RELAY-SESSION-PARAM",
	TLV_TYPE_LABEL_REQ_MSG_ID:          "LABEL-REQ-MSG-ID",
}

func (t TLVType) String() string {
	if n, y := TLVTypeNameMap[t]; y {
		return n
	}
	return fmt.Sprintf("TLVType(%d)", t)
}

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
	case TLV_TYPE_FEC:
		tlv = &FECTLV{}
	case TLV_TYPE_LABEL_GENERIC:
		tlv = &LabelTLV{}
	case TLV_TYPE_ADDRESS_LIST:
		tlv = &AddressListTLV{}
	case TLV_TYPE_STATUS:
		tlv = &StatusTLV{}
	case TLV_TYPE_COMMON_HELLO_PARAM:
		tlv = &CommonHelloParamTLV{}
	case TLV_TYPE_COMMON_SESSION_PARAM:
		tlv = &CommonSessionParamTLV{}
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

const (
	FEC_WILDCARD = 0x01
	FEC_PREFIX   = 0x02
)

type FECElement struct {
	Type   int
	Family int
	Prefix *net.IPNet
}

type FECTLV struct {
	Elements []*FECElement
}

func (t *FECTLV) Decode(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("invalid value length, expects 1 at least not %d", len(data))
	}

	t.Elements = nil

	for len(data) > 0 {
		typ := data[0]
		switch typ {
		case FEC_WILDCARD:
			if len(data) > 1 || len(t.Elements) > 0 {
				return fmt.Errorf("wildcard element must be the only FEC element in the FEC TLV")
			}
			t.Elements = []*FECElement{&FECElement{Type: FEC_WILDCARD}}
			return nil
		case FEC_PREFIX:
			if len(data) < 4 {
				return fmt.Errorf("invalid prefix element length, expects 4 at least not %d", len(data))
			}
			family := int(binary.BigEndian.Uint16(data[1:3]))
			preLen := int(data[3])
			byteLen := (preLen + 7) / 8
			if len(data) < 4+byteLen {
				return fmt.Errorf("invalid prefix element. prefix length field is %d, but remaining buffer len is %d\nbuf: %v", preLen, len(data)-4, data)
			}
			addrLen := 4
			switch family {
			case AFI_IP:
				if preLen > 32 {
					return fmt.Errorf("invalid ipv4 prefix length %d", preLen)
				}
			case AFI_IP6:
				if preLen > 128 {
					return fmt.Errorf("invalid ipv6 prefix length %d", preLen)
				}
				addrLen = 16
			default:
				return fmt.Errorf("unknown address family: %d", family)
			}
			b := make([]byte, addrLen)
			copy(b, data[4:4+byteLen])
			mask := net.CIDRMask(preLen, addrLen*8)
			t.Elements = append(t.Elements, &FECElement{Type: FEC_PREFIX, Family: family, Prefix: &net.IPNet{IP: net.IP(b), Mask: mask}})
			data = data[4+byteLen:]
		}
	}
	return nil
}

func (t *FECTLV) Serialize() ([]byte, error) {
	buf := []byte{}
	for _, e := range t.Elements {
		switch e.Type {
		case FEC_WILDCARD:
			if len(t.Elements) > 0 {
				return nil, fmt.Errorf("wildcard element must be the only FEC element in the FEC TLV")
			}
			return []byte{FEC_WILDCARD}, nil
		case FEC_PREFIX:
			ones, _ := e.Prefix.Mask.Size()
			byteLen := (ones + 7) / 8
			b := make([]byte, byteLen)
			copy(b, e.Prefix.IP)
			// clear trailing bits in the last byte. rfc doesn't require
			// this though.
			if ones%8 != 0 {
				mask := 0xff00 >> (uint(ones) % 8)
				last_byte_value := b[byteLen-1] & byte(mask)
				b[byteLen-1] = last_byte_value
			}
			bbuf := make([]byte, 2)
			binary.BigEndian.PutUint16(bbuf, uint16(e.Family))
			buf = append(buf, []byte{FEC_PREFIX, bbuf[0], bbuf[1], byte(ones)}...)
			buf = append(buf, b...)
		}
	}
	return serializeTLV(t.Type(), buf)
}

func (t *FECTLV) Type() TLVType {
	return TLV_TYPE_FEC
}

func (t *FECTLV) stringifyElements() []string {
	list := make([]string, 0, len(t.Elements))
	for _, e := range t.Elements {
		switch e.Type {
		case FEC_WILDCARD:
			list = append(list, "wildcard")
		case FEC_PREFIX:
			list = append(list, e.Prefix.String())
		}
	}
	return list
}

func (t *FECTLV) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 16))
	buf.WriteString(fmt.Sprintf("[ FEC | %s ]", strings.Join(t.stringifyElements(), ", ")))
	return buf.String()
}

func (t FECTLV) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Typ  TLVType  `json:"type"`
		List []string `json:"list"`
	}{
		Typ:  TLV_TYPE_FEC,
		List: t.stringifyElements(),
	})
}

type LabelTLV struct {
	Label int
}

func (t *LabelTLV) Decode(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("invalid value length, expects 4 at least not %d", len(data))
	}
	label := uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
	t.Label = int(label >> 4)
	return nil
}

func (t *LabelTLV) Serialize() ([]byte, error) {
	buf := make([]byte, 4)
	label := t.Label << 4
	buf[0] = byte((label >> 16) & 0xff)
	buf[1] = byte((label >> 8) & 0xff)
	buf[2] = byte(label & 0xff)
	return serializeTLV(t.Type(), buf)
}

func (t *LabelTLV) Type() TLVType {
	return TLV_TYPE_LABEL_GENERIC
}

func (t *LabelTLV) String() string {
	return fmt.Sprintf("[ LABEL | %d ]", t.Label)
}

func (t *LabelTLV) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Typ   TLVType `json:"type"`
		Label int     `json:"label"`
	}{
		Typ:   TLV_TYPE_LABEL_GENERIC,
		Label: t.Label,
	})
}

const (
	AFI_IP  = 1
	AFI_IP6 = 2
)

type AddressListTLV struct {
	Family int
	List   []net.IP
}

func (t *AddressListTLV) Decode(data []byte) error {
	if len(data) < 2 {
		return fmt.Errorf("invalid value length, expects 2 at least not %d", len(data))
	}
	family := int(binary.BigEndian.Uint16(data[:2]))
	t.Family = family
	var size int
	switch family {
	case AFI_IP:
		size = 4
	case AFI_IP6:
		size = 16
	default:
		return fmt.Errorf("unknown address family %d", family)
	}
	data = data[2:]
	if len(data)%size != 0 {
		return fmt.Errorf("invalid address list. len(%d)%size(%d) != 0 ", len(data), size)
	}
	t.List = make([]net.IP, 0, len(data)/size)
	for len(data) > 0 {
		t.List = append(t.List, net.IP(data[:size]))
		data = data[size:]
	}
	return nil
}

func (t *AddressListTLV) Serialize() ([]byte, error) {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(t.Family))
	switch t.Family {
	case AFI_IP:
		for _, addr := range t.List {
			buf = append(buf, addr.To4()...)
		}
	case AFI_IP6:
		for _, addr := range t.List {
			buf = append(buf, addr.To16()...)
		}
	default:
		return nil, fmt.Errorf("unknown address family: %d", t.Family)
	}
	return serializeTLV(t.Type(), buf)
}

func (t *AddressListTLV) Type() TLVType {
	return TLV_TYPE_ADDRESS_LIST
}

func (t *AddressListTLV) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 16))
	list := make([]string, 0, len(t.List))
	for _, addr := range t.List {
		list = append(list, addr.String())
	}
	buf.WriteString(fmt.Sprintf("[ ADDRESS-LIST | %s ]", strings.Join(list, ", ")))
	return buf.String()
}

func (t *AddressListTLV) MarshalJSON() ([]byte, error) {
	list := make([]string, 0, len(t.List))
	for _, addr := range t.List {
		list = append(list, addr.String())
	}
	return json.Marshal(struct {
		typ    TLVType  `json:"type"`
		family int      `json:"family"`
		list   []string `json:"list"`
	}{
		typ:    TLV_TYPE_ADDRESS_LIST,
		family: t.Family,
		list:   list,
	})
}

type StatusCode uint32

const (
	STATUS_SUCCESS StatusCode = iota
	STATUS_BAD_LDP_ID
	STATUS_BAD_VERSION
	STATUS_BAD_PDU_LEN
	STATUS_UNKNOWN_MSG_TYPE
	STATUS_BAD_MSG_LEN
	STATUS_UNKNOWN_TLV
	STATUS_BAD_TLV_LEN
	STATUS_MALFORMED_TLV_VALUE
	STATUS_HOLD_TIMER_EXPIRED
	STATUS_SHUTDOWN
	STATUS_LOOP_DETECTED
	STATUS_UNKNOWN_FEC
	STATUS_NO_ROUTE
	STATUS_NO_LABEL_RESOURCES
	STATUS_LABEL_RESOURCES_AVAIL
	STATUS_SESSION_REJECTED_NO_HELLO
	STATUS_SESSION_REJECTED_ADV_MODE
	STATUS_SESSION_REJECTED_MAX_PDU_LEN
	STATUS_SESSION_REJECTED_LABEL_RANGE
	STATUS_KEEPALIVE_TIMER_EXPIRED
	STATUS_LABEL_REQ_ABORTED
	STATUS_MISSING_MSG_PARAM
	STATUS_UNSUPPORTED_FAMILY
	STATUS_SESSION_REJECTED_BAD_KEEPALIVE_TIME
	STATUS_INTERNAL_ERROR
)

var StatusCodeNameMap = map[StatusCode]string{
	STATUS_SUCCESS:                             "success",
	STATUS_BAD_LDP_ID:                          "bad-ldp-id",
	STATUS_BAD_VERSION:                         "bad-version",
	STATUS_BAD_PDU_LEN:                         "bad-pdu-len",
	STATUS_UNKNOWN_MSG_TYPE:                    "unknown-msg-type",
	STATUS_BAD_MSG_LEN:                         "bad-msg-len",
	STATUS_UNKNOWN_TLV:                         "unknown-tlv",
	STATUS_BAD_TLV_LEN:                         "bad-tlv-len",
	STATUS_MALFORMED_TLV_VALUE:                 "malformed-tlv-value",
	STATUS_HOLD_TIMER_EXPIRED:                  "hold-timer-expired",
	STATUS_SHUTDOWN:                            "shutdown",
	STATUS_LOOP_DETECTED:                       "loop-detected",
	STATUS_UNKNOWN_FEC:                         "unknown-fec",
	STATUS_NO_ROUTE:                            "no-route",
	STATUS_NO_LABEL_RESOURCES:                  "no-label-resources",
	STATUS_LABEL_RESOURCES_AVAIL:               "label-resources-avail",
	STATUS_SESSION_REJECTED_NO_HELLO:           "no-hello",
	STATUS_SESSION_REJECTED_ADV_MODE:           "bad-adv-mode",
	STATUS_SESSION_REJECTED_MAX_PDU_LEN:        "bad-max-pdu-len",
	STATUS_SESSION_REJECTED_LABEL_RANGE:        "bad-label-range",
	STATUS_KEEPALIVE_TIMER_EXPIRED:             "keepalive-timer-expired",
	STATUS_LABEL_REQ_ABORTED:                   "label-req-aborted",
	STATUS_MISSING_MSG_PARAM:                   "missing-msg-param",
	STATUS_UNSUPPORTED_FAMILY:                  "unsupported-family",
	STATUS_SESSION_REJECTED_BAD_KEEPALIVE_TIME: "bad-keepalive-time",
	STATUS_INTERNAL_ERROR:                      "internal-error",
}

var StatusCodeFlagMap = map[StatusCode]bool{
	STATUS_SUCCESS:                             false,
	STATUS_BAD_LDP_ID:                          true,
	STATUS_BAD_VERSION:                         true,
	STATUS_BAD_PDU_LEN:                         true,
	STATUS_UNKNOWN_MSG_TYPE:                    false,
	STATUS_BAD_MSG_LEN:                         true,
	STATUS_UNKNOWN_TLV:                         false,
	STATUS_BAD_TLV_LEN:                         true,
	STATUS_MALFORMED_TLV_VALUE:                 true,
	STATUS_HOLD_TIMER_EXPIRED:                  true,
	STATUS_SHUTDOWN:                            true,
	STATUS_LOOP_DETECTED:                       false,
	STATUS_UNKNOWN_FEC:                         false,
	STATUS_NO_ROUTE:                            false,
	STATUS_NO_LABEL_RESOURCES:                  false,
	STATUS_LABEL_RESOURCES_AVAIL:               true,
	STATUS_SESSION_REJECTED_NO_HELLO:           true,
	STATUS_SESSION_REJECTED_ADV_MODE:           true,
	STATUS_SESSION_REJECTED_MAX_PDU_LEN:        true,
	STATUS_SESSION_REJECTED_LABEL_RANGE:        true,
	STATUS_KEEPALIVE_TIMER_EXPIRED:             true,
	STATUS_LABEL_REQ_ABORTED:                   false,
	STATUS_MISSING_MSG_PARAM:                   false,
	STATUS_UNSUPPORTED_FAMILY:                  false,
	STATUS_SESSION_REJECTED_BAD_KEEPALIVE_TIME: true,
	STATUS_INTERNAL_ERROR:                      true,
}

func (c StatusCode) String() string {
	return StatusCodeNameMap[c]
}

type StatusTLV struct {
	Code        StatusCode
	E           bool
	F           bool
	MessageID   uint32
	MessageType MessageType
}

func (t *StatusTLV) Decode(data []byte) error {
	if len(data) != 10 {
		return fmt.Errorf("invalid value length, expects 10 not %d", len(data))
	}
	c := binary.BigEndian.Uint32(data[:4])
	if (c & (1 << 31)) > 0 {
		t.E = true
	}
	if (c & (1 << 30)) > 0 {
		t.F = true
	}
	t.Code = StatusCode((c << 2) >> 2) // clear top-most 2 bits
	t.MessageID = binary.BigEndian.Uint32(data[4:8])
	t.MessageType = MessageType(binary.BigEndian.Uint16(data[8:]))
	return nil
}

func (t *StatusTLV) Serialize() ([]byte, error) {
	buf := make([]byte, 10)
	c := uint32(t.Code)
	if t.E {
		c |= 1 << 31
	}
	if t.F {
		c |= 1 << 30
	}
	binary.BigEndian.PutUint32(buf, c)
	binary.BigEndian.PutUint32(buf[4:], uint32(t.MessageID))
	binary.BigEndian.PutUint16(buf[8:], uint16(t.MessageType))
	return serializeTLV(t.Type(), buf)
}

func (t *StatusTLV) Type() TLVType {
	return TLV_TYPE_STATUS
}

func (t *StatusTLV) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 16))
	buf.WriteString(fmt.Sprintf("[ STATUS | code: %s, msg-id: %d, type: %s ]", t.Code, t.MessageID, t.Type))
	return buf.String()
}

func (t *StatusTLV) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		typ     TLVType `json:"type"`
		code    uint32  `json:"code"`
		e       bool    `json:"fatal"`
		f       bool    `json:"forward"`
		msgID   uint32  `json:"msg-id"`
		msgType uint16  `json:"msg-type"`
	}{
		typ:     TLV_TYPE_STATUS,
		code:    uint32(t.Code),
		e:       t.E,
		f:       t.F,
		msgID:   uint32(t.MessageID),
		msgType: uint16(t.MessageType),
	})
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
		typ:      TLV_TYPE_COMMON_HELLO_PARAM,
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

type CommonSessionParamTLV struct {
	ProtocolVersion       uint16
	KeepAliveTime         uint16
	A                     bool  // Label Advertisement Discipline
	D                     bool  // Loop Detection
	PVLim                 uint8 // Path Vector Limit
	MaxPDULength          uint16
	ReceiverLDPIdentifier LDPIdentifier
}

func (t *CommonSessionParamTLV) Decode(data []byte) error {
	if len(data) != 14 {
		return fmt.Errorf("invalid value length. expects 18 not %d", len(data))
	}
	t.ProtocolVersion = binary.BigEndian.Uint16(data[:2])
	t.KeepAliveTime = binary.BigEndian.Uint16(data[2:4])
	if (data[4] & (1 << 7)) > 0 {
		t.A = true
	}
	if (data[4] & (1 << 6)) > 0 {
		t.D = true
	}
	t.PVLim = uint8(data[5])
	t.MaxPDULength = binary.BigEndian.Uint16(data[6:8])
	t.ReceiverLDPIdentifier = LDPIdentifier(data[8:])
	return nil
}

func (t *CommonSessionParamTLV) Serialize() ([]byte, error) {
	buf := make([]byte, 14)
	binary.BigEndian.PutUint16(buf, t.ProtocolVersion)
	binary.BigEndian.PutUint16(buf[2:], t.KeepAliveTime)
	if t.A {
		buf[4] |= 1 << 7
	}
	if t.D {
		buf[4] |= 1 << 6
	}
	buf[5] = t.PVLim
	binary.BigEndian.PutUint16(buf[6:], t.MaxPDULength)
	copy(buf[8:], []byte(t.ReceiverLDPIdentifier))
	return serializeTLV(t.Type(), buf)
}

func (t *CommonSessionParamTLV) Type() TLVType {
	return TLV_TYPE_COMMON_SESSION_PARAM
}

func (t *CommonSessionParamTLV) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 32))
	buf.WriteString(fmt.Sprintf("[ SESSION | proto: %d, keep-alive: %d", t.ProtocolVersion, t.KeepAliveTime))
	if t.A {
		buf.WriteString(", downstream-on-demand")
	} else {
		buf.WriteString(", downstream-unsolicited")
	}
	if t.D {
		buf.WriteString(fmt.Sprintf(", loop detection(max path length: %d)", t.PVLim))
	}
	buf.WriteString(fmt.Sprintf(", max PDU length: %d, receiver label space: %s ]", t.MaxPDULength, t.ReceiverLDPIdentifier))
	return buf.String()
}

func (t *CommonSessionParamTLV) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		typ   TLVType `json:"type"`
		v     uint16  `json:"keep-alive-time"`
		a     bool    `json:"a"`
		d     bool    `json:"d"`
		pvlim uint8   `json:"path-vector-limit"`
		m     uint16  `json:"max-pdu-length"`
		r     string  `json:"receiver-label-space"`
	}{
		typ:   TLV_TYPE_COMMON_SESSION_PARAM,
		v:     t.ProtocolVersion,
		a:     t.A,
		d:     t.D,
		pvlim: t.PVLim,
		m:     t.MaxPDULength,
		r:     t.ReceiverLDPIdentifier.String(),
	})
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
	var msg MessageInterface
	switch typ {
	case MSG_TYPE_NOTIFICATION:
		msg = &NotificationMessage{}
	case MSG_TYPE_HELLO:
		msg = &HelloMessage{}
	case MSG_TYPE_INIT:
		msg = &InitMessage{}
	case MSG_TYPE_KEEPALIVE:
		msg = &KeepAliveMessage{}
	case MSG_TYPE_ADDRESS:
		msg = &AddressMessage{}
	case MSG_TYPE_ADDRESS_WITHDRAW:
		msg = &AddressWithdrawMessage{}
	case MSG_TYPE_LABEL_MAPPING:
		msg = &LabelMappingMessage{}
	case MSG_TYPE_LABEL_REQUEST:
		msg = &LabelRequestMessage{}
	default:
		return nil, nil, fmt.Errorf("unknown msg type %s", typ)
	}
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
	ID() uint32
	SetID(uint32)
	String() string
}

func parseMessage1(data []byte) (uint32, []TLVInterface, error) {
	id := binary.BigEndian.Uint32(data[:4])
	tlvs := make([]TLVInterface, 0, 1)
	data = data[4:]
	for len(data) > 0 {
		tlv, rest, err := parseTLV(data)
		if err != nil {
			return id, nil, err
		}
		tlvs = append(tlvs, tlv)
		data = rest
	}
	return id, tlvs, nil
}

type Message struct {
	id uint32
}

func (m *Message) ID() uint32 {
	return m.id
}

func (m *Message) SetID(id uint32) {
	m.id = id
}

type NotificationMessage struct {
	Message
	Status       *StatusTLV
	OptionalTLVs []TLVInterface
}

func (m *NotificationMessage) Decode(data []byte) error {
	id, tlvs, err := parseMessage1(data)
	if err != nil {
		return err
	}
	m.id = id
	if len(tlvs) < 1 {
		return fmt.Errorf("invalid hello message. no common hello param tlv")
	}
	if tlvs[0].Type() != TLV_TYPE_STATUS {
		return fmt.Errorf("invalid tlv type. expect %s but got %s", TLV_TYPE_STATUS, tlvs[0].Type())
	}
	m.Status = tlvs[0].(*StatusTLV)
	m.OptionalTLVs = tlvs[1:]
	return nil
}

func (m *NotificationMessage) Serialize() ([]byte, error) {
	buf, err := m.Status.Serialize()
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

func (m *NotificationMessage) Type() MessageType {
	return MSG_TYPE_NOTIFICATION
}

func (m *NotificationMessage) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 32))
	buf.WriteString(fmt.Sprintf("[ NOTIF %d | %s", m.ID(), m.Status.String()))
	for _, tlv := range m.OptionalTLVs {
		buf.WriteString(fmt.Sprintf(", %s", tlv.String()))
	}
	buf.WriteString(" ]")
	return buf.String()
}

type HelloMessage struct {
	Message
	CommonHelloParam *CommonHelloParamTLV
	OptionalTLVs     []TLVInterface
}

func (m *HelloMessage) Decode(data []byte) error {
	id, tlvs, err := parseMessage1(data)
	if err != nil {
		return err
	}
	m.id = id
	if len(tlvs) < 1 {
		return fmt.Errorf("invalid hello message. no common hello param tlv")
	}
	if tlvs[0].Type() != TLV_TYPE_COMMON_HELLO_PARAM {
		return fmt.Errorf("invalid tlv type. expect %s but got %s", TLV_TYPE_COMMON_HELLO_PARAM, tlvs[0].Type())
	}
	m.CommonHelloParam = tlvs[0].(*CommonHelloParamTLV)
	m.OptionalTLVs = tlvs[1:]
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

func (m *HelloMessage) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 32))
	buf.WriteString(fmt.Sprintf("[ HELLO %d | %s", m.ID(), m.CommonHelloParam.String()))
	for _, tlv := range m.OptionalTLVs {
		buf.WriteString(fmt.Sprintf(", %s", tlv.String()))
	}
	buf.WriteString(" ]")
	return buf.String()
}

func NewHelloMessage(id uint32, param *CommonHelloParamTLV, optionals []TLVInterface) *HelloMessage {
	return &HelloMessage{
		Message:          Message{id},
		CommonHelloParam: param,
		OptionalTLVs:     optionals,
	}
}

type InitMessage struct {
	Message
	CommonSessionParam *CommonSessionParamTLV
	OptionalTLVs       []TLVInterface
}

func (m *InitMessage) Decode(data []byte) error {
	id, tlvs, err := parseMessage1(data)
	if err != nil {
		return err
	}
	m.id = id
	if len(tlvs) < 1 {
		return fmt.Errorf("invalid hello message. no common hello param tlv")
	}
	if tlvs[0].Type() != TLV_TYPE_COMMON_SESSION_PARAM {
		return fmt.Errorf("invalid tlv type. expect %s but got %s", TLV_TYPE_COMMON_SESSION_PARAM, tlvs[0].Type())
	}
	m.CommonSessionParam = tlvs[0].(*CommonSessionParamTLV)
	m.OptionalTLVs = tlvs[1:]
	return nil
}

func (m *InitMessage) Serialize() ([]byte, error) {
	buf, err := m.CommonSessionParam.Serialize()
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

func (m *InitMessage) Type() MessageType {
	return MSG_TYPE_INIT
}

func (m *InitMessage) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 32))
	buf.WriteString(fmt.Sprintf("[ INIT %d | %s", m.ID(), m.CommonSessionParam.String()))
	for _, tlv := range m.OptionalTLVs {
		buf.WriteString(fmt.Sprintf(", %s", tlv.String()))
	}
	buf.WriteString(" ]")
	return buf.String()
}

type KeepAliveMessage struct {
	Message
	OptionalTLVs []TLVInterface
}

func (m *KeepAliveMessage) Decode(data []byte) error {
	id, tlvs, err := parseMessage1(data)
	if err != nil {
		return err
	}
	m.id = id
	m.OptionalTLVs = tlvs
	return nil
}

func (m *KeepAliveMessage) Serialize() ([]byte, error) {
	return serializeMessage(m.Type(), m.id, nil)
}

func (m *KeepAliveMessage) Type() MessageType {
	return MSG_TYPE_KEEPALIVE
}

func (m *KeepAliveMessage) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 32))
	buf.WriteString(fmt.Sprintf("[ KEEPALIVE %d", m.ID()))
	for idx, tlv := range m.OptionalTLVs {
		if idx == 0 {
			buf.WriteString(" | ")
		} else {
			buf.WriteString(", ")
		}
		buf.WriteString(tlv.String())
	}
	buf.WriteString(" ]")
	return buf.String()
}

type AddressMessage struct {
	Message
	List         *AddressListTLV
	OptionalTLVs []TLVInterface
}

func (m *AddressMessage) Decode(data []byte) error {
	id, tlvs, err := parseMessage1(data)
	if err != nil {
		return err
	}
	m.id = id
	if len(tlvs) < 1 {
		return fmt.Errorf("invalid address message. no address list tlv")
	}
	if tlvs[0].Type() != TLV_TYPE_ADDRESS_LIST {
		return fmt.Errorf("invalid tlv type. expect %s but got %s", TLV_TYPE_ADDRESS_LIST, tlvs[0].Type())
	}
	m.List = tlvs[0].(*AddressListTLV)
	m.OptionalTLVs = tlvs[1:]
	return nil
}

func (m *AddressMessage) Serialize() ([]byte, error) {
	buf, err := m.List.Serialize()
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

func (m *AddressMessage) Type() MessageType {
	return MSG_TYPE_ADDRESS
}

func (m *AddressMessage) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 32))
	buf.WriteString(fmt.Sprintf("[ ADDR %d | %s", m.ID(), m.List.String()))
	for _, tlv := range m.OptionalTLVs {
		buf.WriteString(fmt.Sprintf(", %s", tlv.String()))
	}
	buf.WriteString(" ]")
	return buf.String()
}

type AddressWithdrawMessage struct {
	Message
	List         *AddressListTLV
	OptionalTLVs []TLVInterface
}

func (m *AddressWithdrawMessage) Decode(data []byte) error {
	id, tlvs, err := parseMessage1(data)
	if err != nil {
		return err
	}
	m.id = id
	if len(tlvs) < 1 {
		return fmt.Errorf("invalid address message. no address list tlv")
	}
	if tlvs[0].Type() != TLV_TYPE_ADDRESS_LIST {
		return fmt.Errorf("invalid tlv type. expect %s but got %s", TLV_TYPE_ADDRESS_LIST, tlvs[0].Type())
	}
	m.List = tlvs[0].(*AddressListTLV)
	m.OptionalTLVs = tlvs[1:]
	return nil
}

func (m *AddressWithdrawMessage) Serialize() ([]byte, error) {
	buf, err := m.List.Serialize()
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

func (m *AddressWithdrawMessage) Type() MessageType {
	return MSG_TYPE_ADDRESS_WITHDRAW
}

func (m *AddressWithdrawMessage) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 32))
	buf.WriteString(fmt.Sprintf("[ ADDR-WITHDRAW %d | %s", m.ID(), m.List.String()))
	for _, tlv := range m.OptionalTLVs {
		buf.WriteString(fmt.Sprintf(", %s", tlv.String()))
	}
	buf.WriteString(" ]")
	return buf.String()
}

type LabelMappingMessage struct {
	Message
	FEC          *FECTLV
	Label        *LabelTLV
	OptionalTLVs []TLVInterface
}

func (m *LabelMappingMessage) Decode(data []byte) error {
	id, tlvs, err := parseMessage1(data)
	if err != nil {
		return err
	}
	m.id = id
	if len(tlvs) < 2 {
		return fmt.Errorf("invalid label mapping message. lack of TLV")
	}
	if tlvs[0].Type() != TLV_TYPE_FEC {
		return fmt.Errorf("invalid tlv type. expect %s but got %s", TLV_TYPE_FEC, tlvs[0].Type())
	}
	if tlvs[1].Type() != TLV_TYPE_LABEL_GENERIC {
		return fmt.Errorf("invalid tlv type. expect %s but got %s", TLV_TYPE_LABEL_GENERIC, tlvs[1].Type())
	}
	m.FEC = tlvs[0].(*FECTLV)
	m.Label = tlvs[1].(*LabelTLV)
	m.OptionalTLVs = tlvs[2:]
	return nil
}

func (m *LabelMappingMessage) Serialize() ([]byte, error) {
	buf, err := m.FEC.Serialize()
	if err != nil {
		return nil, err
	}
	buf2, err := m.Label.Serialize()
	if err != nil {
		return nil, err
	}
	buf = append(buf, buf2...)
	for _, o := range m.OptionalTLVs {
		bbuf, err := o.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, bbuf...)
	}
	return serializeMessage(m.Type(), m.id, buf)
}

func (m *LabelMappingMessage) Type() MessageType {
	return MSG_TYPE_LABEL_MAPPING
}

func (m *LabelMappingMessage) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 32))
	buf.WriteString(fmt.Sprintf("[ LABEL-MAPPING %d | %s %s", m.ID(), m.FEC.String(), m.Label.String()))
	for _, tlv := range m.OptionalTLVs {
		buf.WriteString(fmt.Sprintf(", %s", tlv.String()))
	}
	buf.WriteString(" ]")
	return buf.String()
}

type LabelRequestMessage struct {
	Message
	FEC          *FECTLV
	OptionalTLVs []TLVInterface
}

func (m *LabelRequestMessage) Decode(data []byte) error {
	id, tlvs, err := parseMessage1(data)
	if err != nil {
		return err
	}
	m.id = id
	if len(tlvs) < 1 {
		return fmt.Errorf("invalid label mapping message. lack of TLV")
	}
	if tlvs[0].Type() != TLV_TYPE_FEC {
		return fmt.Errorf("invalid tlv type. expect %s but got %s", TLV_TYPE_FEC, tlvs[0].Type())
	}
	m.FEC = tlvs[0].(*FECTLV)
	m.OptionalTLVs = tlvs[1:]
	return nil
}

func (m *LabelRequestMessage) Serialize() ([]byte, error) {
	buf, err := m.FEC.Serialize()
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

func (m *LabelRequestMessage) Type() MessageType {
	return MSG_TYPE_LABEL_MAPPING
}

func (m *LabelRequestMessage) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 32))
	buf.WriteString(fmt.Sprintf("[ LABEL-REQUEST %d | %s", m.ID(), m.FEC.String()))
	for _, tlv := range m.OptionalTLVs {
		buf.WriteString(fmt.Sprintf(", %s", tlv.String()))
	}
	buf.WriteString(" ]")
	return buf.String()
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
