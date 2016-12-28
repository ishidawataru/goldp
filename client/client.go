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

// Package client provides a wrapper for GoLDP's gRPC API
package client

import (
	"time"

	api "github.com/ishidawataru/goldp/api"
	"github.com/ishidawataru/goldp/config"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

type Client struct {
	conn *grpc.ClientConn
	cli  api.GoldpApiClient
}

func defaultGRPCOptions() []grpc.DialOption {
	return []grpc.DialOption{grpc.WithTimeout(time.Second), grpc.WithBlock(), grpc.WithInsecure()}
}

// New returns a new Client using the given target and options for dialing
// to the grpc server. If an error occurs during dialing it will be returned and
// Client will be nil.
func New(target string, opts ...grpc.DialOption) (*Client, error) {
	return NewWith(context.Background(), target, opts...)
}

// NewWith is like New, but uses the given ctx to cancel or expire the current
// attempt to connect if it becomes Done before the connection succeeds.
func NewWith(ctx context.Context, target string, opts ...grpc.DialOption) (*Client, error) {
	if target == "" {
		target = ":50052"
	}
	if len(opts) == 0 {
		opts = defaultGRPCOptions()
	}
	conn, err := grpc.DialContext(ctx, target, opts...)
	if err != nil {
		return nil, err
	}
	cli := api.NewGoldpApiClient(conn)
	return &Client{conn: conn, cli: cli}, nil
}

// NewFrom returns a new Client, using the given conn and cli for the
// underlying connection. The given grpc.ClientConn connection is expected to be
// initialized and paired with the api client. See New to have the connection
// dialed for you.
func NewFrom(conn *grpc.ClientConn, cli api.GoldpApiClient) *Client {
	return &Client{conn: conn, cli: cli}
}

func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) GetServer() (*config.Global, error) {
	ret, err := c.cli.GetServer(context.Background(), &api.GetServerRequest{})
	if err != nil {
		return nil, err
	}
	g := ret.Server.ToConfig()
	return &g, nil
}

func (c *Client) StartServer(global *config.Global) error {
	s := &api.Server{}
	s.FromConfig(global)
	_, err := c.cli.StartServer(context.Background(), &api.StartServerRequest{
		Server: s,
	})
	return err
}

func (c *Client) StopServer() error {
	_, err := c.cli.StopServer(context.Background(), &api.StopServerRequest{})
	return err
}

func (c *Client) ListInterface() ([]config.Interface, error) {
	ret, err := c.cli.ListInterface(context.Background(), &api.ListInterfaceRequest{})
	if err != nil {
		return nil, err
	}
	is := make([]config.Interface, 0, len(ret.Interfaces))
	for _, j := range ret.Interfaces {
		is = append(is, j.ToConfig())
	}
	return is, nil
}

func (c *Client) AddInterface(intf *config.Interface) error {
	i := &api.Interface{}
	i.FromConfig(intf)
	_, err := c.cli.AddInterface(context.Background(), &api.AddInterfaceRequest{
		Interface: i,
	})
	return err
}

func (c *Client) DeleteInterface(intf *config.Interface) error {
	i := &api.Interface{}
	i.FromConfig(intf)
	_, err := c.cli.DeleteInterface(context.Background(), &api.DeleteInterfaceRequest{
		Interface: i,
	})
	return err
}

func (c *Client) ListSession() ([]config.Session, error) {
	ret, err := c.cli.ListSession(context.Background(), &api.ListSessionRequest{})
	if err != nil {
		return nil, err
	}
	is := make([]config.Session, 0, len(ret.Sessions))
	for _, j := range ret.Sessions {
		is = append(is, j.ToConfig())
	}
	return is, nil
}

func (c *Client) AddInterfaceAddress(intf *config.Interface) error {
	i := &api.Interface{}
	i.FromConfig(intf)
	_, err := c.cli.AddInterfaceAddress(context.Background(), &api.AddInterfaceAddressRequest{
		Interface: i,
	})
	return err
}

func (c *Client) DeleteInterfaceAddress(intf *config.Interface) error {
	i := &api.Interface{}
	i.FromConfig(intf)
	_, err := c.cli.DeleteInterfaceAddress(context.Background(), &api.DeleteInterfaceAddressRequest{
		Interface: i,
	})
	return err
}

func (c *Client) AddLocalLabelMapping(label int, fec ...string) error {
	_, err := c.cli.AddLocalLabelMapping(context.Background(), &api.AddLocalLabelMappingRequest{
		FEC:   fec,
		Label: uint32(label),
	})
	return err
}

func (c *Client) DeleteLocalLabelMapping(fec ...string) error {
	_, err := c.cli.DeleteLocalLabelMapping(context.Background(), &api.DeleteLocalLabelMappingRequest{
		FEC: fec,
	})
	return err
}

func (c *Client) GetLabelMapping(prefix string) (config.Mapping, error) {
	res, err := c.cli.GetLabelMapping(context.Background(), &api.GetLabelMappingRequest{
		Prefix: prefix,
	})
	if err != nil {
		return config.Mapping{}, err
	}
	return res.Mapping.ToConfig(), nil
}

func (c *Client) ListLabelMapping() ([]config.Mapping, error) {
	res, err := c.cli.ListLabelMapping(context.Background(), &api.ListLabelMappingRequest{})
	if err != nil {
		return nil, err
	}
	list := make([]config.Mapping, 0, len(res.Mapping))
	for _, m := range res.Mapping {
		list = append(list, m.ToConfig())
	}
	return list, nil
}

type MonitorSessionClient struct {
	stream api.GoldpApi_MonitorSessionClient
}

func (c *MonitorSessionClient) Recv() (config.Session, error) {
	d, err := c.stream.Recv()
	if err != nil {
		return config.Session{}, err
	}
	return d.Session.ToConfig(), nil
}

func (c *Client) MonitorSession() (*MonitorSessionClient, error) {
	stream, err := c.cli.MonitorSession(context.Background(), &api.MonitorSessionRequest{})
	if err != nil {
		return nil, err
	}
	return &MonitorSessionClient{stream}, nil
}
