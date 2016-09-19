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

	"github.com/apex/log"
	"github.com/ishidawataru/goldp/config"
	"github.com/spf13/viper"
)

type ConfigManager struct {
	ReloadCh  chan struct{}
	file      string
	format    string
	waiting   bool
	doneCh    chan struct{}
	ldpServer *LDPServer
}

func NewConfigManager(file, format string, ldpServer *LDPServer) *ConfigManager {
	m := &ConfigManager{
		ReloadCh:  make(chan struct{}, 1),
		file:      file,
		format:    format,
		doneCh:    make(chan struct{}),
		ldpServer: ldpServer,
	}
	m.ReloadCh <- struct{}{}
	return m
}

func (m *ConfigManager) WaitReload() error {
	if m.waiting {
		return fmt.Errorf("already waiting")
	}
	m.waiting = true
	<-m.doneCh
	m.waiting = false
	return nil
}

func (m *ConfigManager) Serve() {
	for {
		<-m.ReloadCh
		v := viper.New()
		v.SetConfigFile(m.file)
		v.SetConfigType(m.format)
		if err := v.ReadInConfig(); err != nil {
			log.Fatalf("%s", err)
		}

		c := &config.Config{}

		if err := v.UnmarshalExact(c); err != nil {
			log.Fatalf("%s", err)
		}

		if err := config.SetDefault(c); err != nil {
			log.Fatalf("%s", err)
		}

		if c.Global.RouterId != "" {
			err := m.ldpServer.StartServer(c.Global)
			if err != nil {
				log.Warnf("failed to start server: %s", err)
			}
		}

		intfs, _ := m.ldpServer.ListInterface()

		for _, i := range intfs {
			found := false
			for _, j := range c.Interfaces {
				if i.Name == j.Name || i.Index == j.Index {
					found = true
					break
				}
			}
			if !found {
				err := m.ldpServer.DeleteInterface(i)
				if err != nil {
					log.Warnf("failed to delete intf: %s", err)
				}
			}
		}

		for _, i := range c.Interfaces {
			err := m.ldpServer.AddInterface(i)
			if err != nil {
				log.Warnf("failed to add intf: %s", err)
			}
		}

		select {
		case m.doneCh <- struct{}{}:
		default:
		}
	}
}
