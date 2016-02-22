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
	"github.com/apex/log"
	"github.com/ishidawataru/goldp/api"
	"github.com/spf13/viper"
)

const (
	DEFAULT_HOLDTIME = 15
)

type Interface struct {
	Name   string `mapstructure:"name"`
	Index  int    `mapstructure:"index"`
	Status int    `mapstructure:"status"`
}

type Global struct {
	RouterId     string `mapstructure:"router-id"`
	HoldTime     int    `mapstructure:"hold-time"`
	LocalAddress string `mapstructure:"local-address"`
}

type Config struct {
	Global     Global      `mapstructure:"global"`
	Interfaces []Interface `mapstructure:"interfaces"`
}

func SetDefault(v *viper.Viper, c *Config) error {
	if v == nil {
		v = viper.New()
	}

	if !v.IsSet("global.hold-time") {
		c.Global.HoldTime = DEFAULT_HOLDTIME
	}

	//	if !v.IsSet("interfaces") {
	//		if intfs, err := net.Interfaces(); err != nil {
	//			return err
	//		} else {
	//			c.Interfaces = make([]Interface, 0, len(intfs))
	//			log.Debugf("intfs:", intfs)
	//			for _, intf := range intfs {
	//				if intf.Flags&net.FlagLoopback > 0 {
	//					continue
	//				}
	//				log.Debugf("add intf %s", intf.Name)
	//				c.Interfaces = append(c.Interfaces, Interface{
	//					Name:  intf.Name,
	//					Index: intf.Index,
	//				})
	//			}
	//		}
	//	}

	return nil
}

type ConfigManager struct {
	ReloadCh chan struct{}
	reqCh    chan *api.Request
	file     string
	format   string
}

func NewConfigManager(file, format string, reqCh chan *api.Request) *ConfigManager {
	m := &ConfigManager{
		ReloadCh: make(chan struct{}, 1),
		reqCh:    reqCh,
		file:     file,
		format:   format,
	}
	m.ReloadCh <- struct{}{}
	return m
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

		c := &Config{}

		if err := v.UnmarshalExact(c); err != nil {
			log.Fatalf("%s", err)
		}

		if err := SetDefault(v, c); err != nil {
			log.Fatalf("%s", err)
		}

		ch := make(chan *api.Response)
		req := &api.Request{
			Type:  api.SET_GLOBAL,
			Data:  c.Global,
			ResCh: ch,
			From:  api.CONFIG_MANAGER,
		}
		m.reqCh <- req
		if res := <-ch; res.Error != nil {
			log.Fatalf("%s", res.Error)
		}

		for _, name := range c.Interfaces {
			ch := make(chan *api.Response)
			req := &api.Request{
				Type:  api.ADD_INTF,
				Data:  name,
				ResCh: ch,
				From:  api.CONFIG_MANAGER,
			}
			m.reqCh <- req
			if res := <-ch; res.Error != nil {
				log.Fatalf("%s", res.Error)
			}
		}
	}
}
