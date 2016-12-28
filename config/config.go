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

package config

import (
	"fmt"
)

const (
	DEFAULT_HELLO_INTERVAL  = 5
	DEFAULT_KEEP_ALIVE_TIME = 10
	DEFAULT_MAX_PDU_LENGTH  = 4096
)

// maybe it is good idea to hold all value as string
// to distinguish the value is not specified by the user ("")

type Mapping struct {
	Prefix string         `mapstructure:"prefix"`
	Local  int            `mapstructure:"local-label"`
	Remote map[string]int `mapstructure:"remote-label"`
}

const (
	SESSION_STATE_NON_EXISTENT = "non-existent"
	SESSION_STATE_INITIALIZED  = "initialized"
	SESSION_STATE_OPENREC      = "openrec"
	SESSION_STATE_OPENSENT     = "opensent"
	SESSION_STATE_OPERATIONAL  = "operational"
)

type Session struct {
	LocalId       string       `mapstructure:"local-id"`
	PeerId        string       `mapstructure:"peer-id"`
	KeepAliveTime int          `mapstructure:"keep-alive-time"`
	MaxPDULength  int          `mapstructure:"max-pdu-length"`
	LoopDetection bool         `mapstructure:"loop-detection"`
	PVLim         int          `mapstructure:"path-vector-limit"`
	LabelAdvMode  LabelAdvMode `mapstructure:"label-adv-mode"`
	PrevFSMState  string       `mapstructure:"prev-fsm-state"`
	FSMState      string       `mapstructure:"fsm-state"`
}

type Interface struct {
	Name      string   `mapstructure:"name"`
	Index     int      `mapstructure:"index"`
	Status    int      `mapstructure:"status"`
	Addresses []string `mapstructure:"addresses"`
}

type LabelAdvMode string

const (
	DOD LabelAdvMode = "dod" // Downstream on Demand
	DU  LabelAdvMode = "du"  // Downstream Unsolicited
)

var LabelAdvModeToIntMap = map[LabelAdvMode]int{
	DOD: 0,
	DU:  1,
}

var IntToLabelAdvModeMap = map[int]LabelAdvMode{
	0: DOD,
	1: DU,
}

func (v LabelAdvMode) Validate() error {
	if _, ok := LabelAdvModeToIntMap[v]; !ok {
		return fmt.Errorf("invalid LabelAdvMode: %s", v)
	}
	return nil
}

func (v LabelAdvMode) Default() LabelAdvMode {
	return DU
}

type Global struct {
	RouterId      string       `mapstructure:"router-id"`
	HoldTime      int          `mapstructure:"hold-time"`
	LocalAddress  string       `mapstructure:"local-address"`
	HelloInterval int          `mapstructure:"hello-interval"`
	KeepAliveTime int          `mapstructure:"keep-alive-time"`
	MaxPDULength  int          `mapstructure:"max-pdu-length"`
	LoopDetection bool         `mapstructure:"loop-detection"`
	PVLim         int          `mapstructure:"path-vector-limit"`
	LabelAdvMode  LabelAdvMode `mapstructure:"label-adv-mode"`
}

type Config struct {
	Global     Global      `mapstructure:"global"`
	Interfaces []Interface `mapstructure:"interfaces"`
}

type State struct {
	Global     Global             `mapstructure:"global"`
	Interfaces []Interface        `mapstructure:"interfaces"`
	Sessions   map[string]Session `mapstructure:"sessions"`
}

func SetGlobalDefault(c *Global) error {
	if c.HelloInterval == 0 {
		c.HelloInterval = DEFAULT_HELLO_INTERVAL
	}

	if c.HoldTime == 0 {
		c.HoldTime = DEFAULT_HELLO_INTERVAL * 3
	}

	if c.KeepAliveTime == 0 {
		c.KeepAliveTime = DEFAULT_KEEP_ALIVE_TIME
	}

	if c.MaxPDULength == 0 {
		c.MaxPDULength = DEFAULT_MAX_PDU_LENGTH
	}

	if c.LabelAdvMode == "" {
		c.LabelAdvMode = c.LabelAdvMode.Default()
	}
	return nil
}

func SetDefault(c *Config) error {
	return SetGlobalDefault(&c.Global)
}
