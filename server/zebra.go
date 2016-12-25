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
	"github.com/osrg/gobgp/zebra"
)

type ZebraClient struct {
	cli       *zebra.Client
	ldpServer *Server
}

func NewZebraClient(network, address string, ldpServer *Server) *ZebraClient {
	cli, err := zebra.NewClient(network, address, zebra.ROUTE_BGP, 2)
	if err != nil {
		log.Fatalf("%s", err)
	}
	return &ZebraClient{
		cli:       cli,
		ldpServer: ldpServer,
	}
}

func (z *ZebraClient) Serve() {
	z.cli.SendRouterIDAdd()
	z.cli.SendInterfaceAdd()
	z.cli.SendRedistribute(zebra.ROUTE_OSPF, 0)

	for {
		m := <-z.cli.Receive()
		log.Debugf("%s", m)
		switch m.Header.Command {
		case zebra.ROUTER_ID_UPDATE:
			b := m.Body.(*zebra.RouterIDUpdateBody)
			global := config.Global{}
			config.SetGlobalDefault(&global)
			global.RouterId = b.Prefix.String()
			s, err := z.ldpServer.StartServer(global)
			if err != nil {
				log.Warnf("%s", err)
			}
			z.ldpServer = s
			//		case zebra.INTERFACE_ADD:
			//			b := m.Body.(*zebra.InterfaceUpdateBody)
		case zebra.INTERFACE_ADDRESS_ADD:
			b := m.Body.(*zebra.InterfaceAddressUpdateBody)
			i := config.Interface{
				Index:     int(b.Index),
				Addresses: []string{fmt.Sprintf("%s/%d", b.Prefix, b.Length)},
			}
			err := z.ldpServer.AddInterfaceAddress(i)
			if err != nil {
				log.Warnf("%s", err)
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
