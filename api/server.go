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

	"github.com/apex/log"
	"github.com/ishidawataru/goldp/config"
	"github.com/ishidawataru/goldp/server"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

type GRPCServer struct {
	ldpServer  *server.Server
	grpcServer *grpc.Server
	hosts      string
}

func NewGRPCServer(hosts string, ldpServer *server.Server) *GRPCServer {
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

func (m *Server) ToConfig() config.Global {
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

func (m *Server) FromConfig(c *config.Global) {
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

func (m *Interface) ToConfig() config.Interface {
	return config.Interface{
		Name:      m.Name,
		Addresses: m.Addresses,
	}
}

func (m *Interface) FromConfig(c *config.Interface) {
	m.Name = c.Name
	m.Addresses = c.Addresses
}

func (m *Session) ToConfig() config.Session {
	return config.Session{
		LocalId:       m.LocalId,
		PeerId:        m.PeerId,
		KeepAliveTime: int(m.KeepAliveTime),
		MaxPDULength:  int(m.MaxPduLength),
		LoopDetection: m.LoopDetection,
		PVLim:         int(m.PathVectorLimit),
		LabelAdvMode:  config.IntToLabelAdvModeMap[int(m.LabelAdvMode)],
		PrevFSMState:  m.PrevFsmState,
		FSMState:      m.FsmState,
	}
}

func (m *Session) FromConfig(c *config.Session) {
	m.LocalId = c.LocalId
	m.PeerId = c.PeerId
	m.KeepAliveTime = uint32(c.KeepAliveTime)
	m.MaxPduLength = uint32(c.MaxPDULength)
	m.LoopDetection = c.LoopDetection
	m.PathVectorLimit = uint32(c.PVLim)
	m.LabelAdvMode = LabelAdvMode(config.LabelAdvModeToIntMap[c.LabelAdvMode])
	m.PrevFsmState = c.PrevFSMState
	m.FsmState = c.FSMState
}

func (g *GRPCServer) StartServer(ctx context.Context, arg *StartServerRequest) (*StartServerResponse, error) {
	if arg.Server == nil {
		return nil, fmt.Errorf("invalid request: server is nil")
	}
	s, err := g.ldpServer.StartServer(arg.Server.ToConfig())
	g.ldpServer = s
	return &StartServerResponse{}, err
}

func (g *GRPCServer) StopServer(ctx context.Context, arg *StopServerRequest) (*StopServerResponse, error) {
	err := g.ldpServer.Stop()
	if err == nil {
		g.ldpServer = nil
	}
	return &StopServerResponse{}, err
}

func (g *GRPCServer) GetServer(ctx context.Context, arg *GetServerRequest) (*GetServerResponse, error) {
	c, err := g.ldpServer.GetConfig()
	if err != nil {
		return nil, err
	}
	s := &Server{}
	s.FromConfig(&c.Global)
	return &GetServerResponse{s}, nil
}

func (g *GRPCServer) AddInterface(_ context.Context, arg *AddInterfaceRequest) (*AddInterfaceResponse, error) {
	if arg.Interface == nil {
		return nil, fmt.Errorf("invalid request: interface is nil")
	}
	err := g.ldpServer.AddInterface(arg.Interface.ToConfig())
	return &AddInterfaceResponse{}, err
}

func (g *GRPCServer) DeleteInterface(_ context.Context, arg *DeleteInterfaceRequest) (*DeleteInterfaceResponse, error) {
	if arg.Interface == nil {
		return nil, fmt.Errorf("invalid request: interface is nil")
	}
	err := g.ldpServer.DeleteInterface(arg.Interface.ToConfig())
	return &DeleteInterfaceResponse{}, err
}

func (g *GRPCServer) ListInterface(_ context.Context, _ *ListInterfaceRequest) (*ListInterfaceResponse, error) {
	c, err := g.ldpServer.ListInterface()
	if err != nil {
		return nil, err
	}
	is := make([]*Interface, 0, len(c))
	for _, j := range c {
		i := &Interface{}
		i.FromConfig(&j)
		is = append(is, i)
	}
	return &ListInterfaceResponse{
		Interfaces: is,
	}, nil
}

func (g *GRPCServer) ListSession(_ context.Context, _ *ListSessionRequest) (*ListSessionResponse, error) {
	c, err := g.ldpServer.ListSession()
	if err != nil {
		return nil, err
	}
	ss := make([]*Session, 0, len(c))
	for _, j := range c {
		i := &Session{}
		i.FromConfig(&j)
		ss = append(ss, i)
	}
	return &ListSessionResponse{
		Sessions: ss,
	}, nil
}

func (g *GRPCServer) AddInterfaceAddress(_ context.Context, arg *AddInterfaceAddressRequest) (*AddInterfaceAddressResponse, error) {
	if arg.Interface == nil {
		return nil, fmt.Errorf("invalid request: interface is nil")
	}
	err := g.ldpServer.AddInterfaceAddress(arg.Interface.ToConfig())
	return &AddInterfaceAddressResponse{}, err
}

func (g *GRPCServer) DeleteInterfaceAddress(_ context.Context, arg *DeleteInterfaceAddressRequest) (*DeleteInterfaceAddressResponse, error) {
	if arg.Interface == nil {
		return nil, fmt.Errorf("invalid request: interface is nil")
	}
	err := g.ldpServer.DeleteInterfaceAddress(arg.Interface.ToConfig())
	return &DeleteInterfaceAddressResponse{}, err
}

func (g *GRPCServer) AddLocalLabelMapping(_ context.Context, arg *AddLocalLabelMappingRequest) (*AddLocalLabelMappingResponse, error) {
	return &AddLocalLabelMappingResponse{}, g.ldpServer.AddLocalLabelMapping(int(arg.Label), arg.FEC...)
}

func (g *GRPCServer) DeleteLocalLabelMapping(_ context.Context, arg *DeleteLocalLabelMappingRequest) (*DeleteLocalLabelMappingResponse, error) {
	return &DeleteLocalLabelMappingResponse{}, g.ldpServer.DeleteLocalLabelMapping(arg.FEC...)
}

func (g *GRPCServer) GetLocalLabelMapping(_ context.Context, arg *GetLocalLabelMappingRequest) (*GetLocalLabelMappingResponse, error) {
	label, err := g.ldpServer.GetLocalLabelMapping(arg.FEC)
	if err != nil {
		return nil, err
	}
	return &GetLocalLabelMappingResponse{
		Label: uint32(label),
	}, nil
}

func (g *GRPCServer) GetRemoteLabelMapping(_ context.Context, arg *GetRemoteLabelMappingRequest) (*GetRemoteLabelMappingResponse, error) {
	label, err := g.ldpServer.GetRemoteLabelMapping(arg.FEC, arg.Nexthop)
	if err != nil {
		return nil, err
	}
	return &GetRemoteLabelMappingResponse{
		Label: uint32(label),
	}, nil
}

func (g *GRPCServer) MonitorSession(_ *MonitorSessionRequest, stream GoldpApi_MonitorSessionServer) error {
	w, err := g.ldpServer.MonitorSession()
	if err != nil {
		return err
	}
	defer w.Stop()

	for {
		e := w.Next()
		s := e.Data.(config.Session)
		log.Debugf("event: %d %#v", e.Type, s)
		i := &Session{}
		i.FromConfig(&s)
		if err := stream.Send(&MonitorSessionResponse{
			Session: i,
		}); err != nil {
			return err
		}
	}
}
