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

//import (
//	"fmt"
//	api "github.com/ishidawataru/goldp/api"
//	"golang.org/x/net/context"
//	"google.golang.org/grpc"
//	"net"
//)
//
//type ReqType uint8
//
//const (
//	REQ_GLOBAL ReqType = iota
//	REQ_SET_GLOBAL
//	REQ_HELLO_TABLE
//)
//
//type Server struct {
//	grpcServer  *grpc.Server
//	ldpServerCh chan *GrpcRequest
//	port        int
//}
//
//func (s *Server) Serve() error {
//	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
//	if err != nil {
//		return fmt.Errorf("failed to listen: %v", err)
//	}
//	s.grpcServer.Serve(lis)
//	return nil
//}
//
//func (s *Server) get(typ ReqType, d interface{}) (interface{}, error) {
//	req := NewGrpcRequest(typ, d)
//	s.ldpServerCh <- req
//	res := <-req.ResponseCh
//	if res.Err != nil {
//		return nil, res.Err
//	}
//	return res.Data, nil
//}
//
//func (s *Server) GetGlobal(ctx context.Context, _ *api.Global) (*api.Global, error) {
//	d, err := s.get(REQ_GLOBAL, nil)
//	if err != nil {
//		return nil, err
//	}
//	return d.(*api.Global), nil
//}
//
//func (s *Server) SetGlobal(ctx context.Context, global *api.Global) (*api.None, error) {
//	_, err := s.get(REQ_SET_GLOBAL, global)
//	if err != nil {
//		return nil, err
//	}
//	return nil, nil
//}
//
//func (s *Server) GetHelloTable(ctx context.Context, _ *api.HelloTable) (*api.HelloTable, error) {
//	d, err := s.get(REQ_HELLO_TABLE, nil)
//	if err != nil {
//		return nil, err
//	}
//	return d.(*api.HelloTable), nil
//}
//
//type GrpcRequest struct {
//	Type       ReqType
//	ResponseCh chan *GrpcResponse
//	Err        error
//	Data       interface{}
//}
//
//func NewGrpcRequest(reqType ReqType, d interface{}) *GrpcRequest {
//	return &GrpcRequest{
//		Type:       reqType,
//		ResponseCh: make(chan *GrpcResponse, 8),
//		Data:       d,
//	}
//}
//
//type GrpcResponse struct {
//	Err  error
//	Data interface{}
//}
//
//func NewGrpcServer(port int, ldpServerCh chan *GrpcRequest) *Server {
//	grpcServer := grpc.NewServer()
//	server := &Server{
//		grpcServer:  grpcServer,
//		ldpServerCh: ldpServerCh,
//		port:        port,
//	}
//	api.RegisterGoldpApiServer(grpcServer, server)
//	return server
//}
