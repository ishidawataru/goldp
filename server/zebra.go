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
	"github.com/ishidawataru/goldp/api"
	"github.com/ishidawataru/goldp/config"
	"github.com/osrg/gobgp/zebra"
)

type ZebraClient struct {
	cli   *zebra.Client
	reqCh chan *api.Request
}

func NewZebraClient(network, address string, reqCh chan *api.Request) *ZebraClient {
	cli, err := zebra.NewClient(network, address, zebra.ROUTE_BGP)
	if err != nil {
		log.Fatalf("%s", err)
	}
	return &ZebraClient{
		cli:   cli,
		reqCh: reqCh,
	}
}

func (z *ZebraClient) Serve() {
	z.cli.SendRouterIDAdd()
	z.cli.SendInterfaceAdd()
	z.cli.SendRedistribute(zebra.ROUTE_OSPF)

	for {
		m := <-z.cli.Receive()
		log.Debugf("%s", m)
		switch m.Header.Command {
		case zebra.ROUTER_ID_UPDATE:
			ch := make(chan *api.Response)
			z.reqCh <- &api.Request{
				Type:  api.GET_GLOBAL,
				ResCh: ch,
			}
			res := <-ch
			if res.Error != nil {
				log.Fatalf("%s", res.Error)
			}

			global := res.Data.(config.Global)
			if global.RouterId != "" {
				log.Debugf("router-id is already set")
				continue
			}
			b := m.Body.(*zebra.RouterIDUpdateBody)
			global.RouterId = b.Prefix.String()
			log.Debugf("global: %s", global)
			z.reqCh <- &api.Request{
				Type: api.SET_GLOBAL,
				Data: global,
				From: api.ZEBRA_CLIENT,
			}
			//		case zebra.INTERFACE_ADD:
			//			b := m.Body.(*zebra.InterfaceUpdateBody)
			//			log.Debugf("intf %v", res.Data.(config.Interface))
		case zebra.INTERFACE_ADDRESS_ADD:
			b := m.Body.(*zebra.InterfaceAddressUpdateBody)
			ch := make(chan *api.Response)
			z.reqCh <- &api.Request{
				Type:  api.GET_INTF,
				ResCh: ch,
				Data: config.Interface{
					Index: int(b.Index),
				},
			}
			res := <-ch
			if res.Error != nil {
				log.Debugf("interface %s is not configured", b.Index)
				continue
			}
			z.reqCh <- &api.Request{
				Type: api.ADD_ADDRESS,
				Data: config.Interface{
					Index:     int(b.Index),
					Addresses: []string{fmt.Sprintf("%s/%d", b.Prefix, b.Length)},
				},
			}

			//			if intf.Flags&net.FlagLoopback > 0 {
			//				continue
			//			}
			//			z.reqCh <- &api.Request{
			//				Type: api.ADD_INTF,
			//				Data: config.Interface{
			//					Name:   b.Name,
			//					Index:  int(b.Index),
			//					Status: int(b.Status),
			//				},
			//			}
		}
	}
}
