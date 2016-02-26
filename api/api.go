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

package api

type ReqType uint8

const (
	SET_GLOBAL ReqType = iota
	GET_GLOBAL
	ADD_INTF
	DEL_INTF
	SET_INTF
	ADD_ADDRESS
	GET_INTF
	GET_INTFS
	ADD_ROUTE
	DEL_ROUTE
	GET_ROUTE
	GET_ROUTES
)

type SourceType uint8

const (
	CONFIG_MANAGER SourceType = iota
	ZEBRA_CLIENT
	GRPC_SERVER
)

type Request struct {
	Type  ReqType
	Data  interface{}
	ResCh chan *Response
	From  SourceType
}

type Response struct {
	Error error
	Data  interface{}
}
