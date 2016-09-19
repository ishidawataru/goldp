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

package goldpapi

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/ishidawataru/goldp/config"
	"github.com/ishidawataru/goldp/server"
)

type GRPCServer struct {
	ldpServer  *server.LDPServer
	grpcServer *grpc.Server
	hosts      string
}

func NewGRPCServer(hosts string, ldpServer *server.LDPServer) *GRPCServer {
	grpc.EnableTracing = false
	grpcServer := grpc.NewServer()
	server := &GRPCServer{
		ldpServer:  ldpServer,
		grpcServer: grpcServer,
		hosts:      hosts,
	}
	RegisterGoldpApiServer(grpcServer, server)
	return server
}

func (g *GRPCServer) Serve() error {
	var wg sync.WaitGroup
	l := strings.Split(g.hosts, ",")
	wg.Add(len(l))
	serve := func(host string) {
		defer wg.Done()
		lis, err := net.Listen("tcp", fmt.Sprintf(host))
		if err != nil {
			return
		}
		g.grpcServer.Serve(lis)
	}
	for _, host := range l {
		go serve(host)
	}
	wg.Wait()
	return nil
}

func (m *Server) toConfig() config.Global {
	return config.Global{
		RouterId:      m.RouterId,
		HoldTime:      int(m.HoldTime),
		LocalAddress:  m.LocalAddress,
		HelloInterval: int(m.HelloInterval),
		KeepAliveTime: int(m.KeepAliveTime),
		MaxPDULength:  int(m.MaxPduLength),
		LoopDetection: m.LoopDetection,
		PVLim:         int(m.PathVectorLimit),
		LabelAdvMode:  config.IntToLabelAdvModeMap[int(m.LabelAdvMode)],
	}
}

func (m *Server) fromConfig(c *config.Global) {
	m.RouterId = c.RouterId
	m.HoldTime = uint32(c.HoldTime)
	m.LocalAddress = c.LocalAddress
	m.HelloInterval = uint32(c.HelloInterval)
	m.KeepAliveTime = uint32(c.KeepAliveTime)
	m.MaxPduLength = uint32(c.MaxPDULength)
	m.LoopDetection = c.LoopDetection
	m.PathVectorLimit = uint32(c.PVLim)
	m.LabelAdvMode = LabelAdvMode(config.LabelAdvModeToIntMap[c.LabelAdvMode])
}

func (g *GRPCServer) StartServer(ctx context.Context, arg *StartServerRequest) (*StartServerResponse, error) {
	if arg.Server == nil {
		return nil, fmt.Errorf("invalid request: server is nil")
	}
	err := g.ldpServer.StartServer(arg.Server.toConfig())
	return &StartServerResponse{}, err
}

func (g *GRPCServer) StopServer(ctx context.Context, arg *StopServerRequest) (*StopServerResponse, error) {
	err := g.ldpServer.StopServer()
	return &StopServerResponse{}, err
}

func (g *GRPCServer) GetServer(ctx context.Context, arg *GetServerRequest) (*GetServerResponse, error) {
	c, err := g.ldpServer.GetConfig()
	if err != nil {
		return nil, err
	}
	s := &Server{}
	s.fromConfig(&c.Global)
	return &GetServerResponse{s}, nil
}
