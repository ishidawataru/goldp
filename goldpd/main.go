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

package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/apex/log"
	"github.com/apex/log/handlers/cli"
	api "github.com/ishidawataru/goldp/api"
	"github.com/ishidawataru/goldp/server"
	"github.com/jessevdk/go-flags"
)

func main() {
	var opts struct {
		DisableGRPC bool   `long:"disable-grpc" description:"disable grpc api server"`
		GRPCHosts   string `long:"grpc-hosts" description:"grpc port" default:":50052"`
		LogLevel    string `short:"l" long:"log-level" description:"log level" default:"info"`
		ConfigFile  string `short:"f" long:"config-file" description:"specifying a config file"`
		ConfigType  string `short:"t" long:"config-type" description:"specifying config type (toml, yaml, json)" default:"yaml"`
		EnableZebra bool   `long:"enable-zebra" description:"enable zebra"`
		SocketFile  string `long:"zebra-socket-file" description:"zapi unix domain socket" default:"/var/run/quagga/zserv.api"`
	}

	log.SetHandler(cli.Default)
	log.SetLevel(log.InfoLevel)

	_, err := flags.Parse(&opts)
	if err != nil {
		log.Fatalf("%s", err)
	}

	if opts.LogLevel == "debug" {
		log.SetLevel(log.DebugLevel)
	}

	ldpServer := server.New()

	if opts.ConfigFile != "" {
		configManager := server.NewConfigManager(opts.ConfigFile, opts.ConfigType, ldpServer)
		go configManager.Serve()

		// ensure config via config-file finishes prior to config via zebra
		configManager.WaitReload()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGHUP)
		go func() {
			for {
				switch <-sigCh {
				case syscall.SIGHUP:
					configManager.ReloadCh <- struct{}{}
				}
			}
		}()
	}

	if opts.EnableZebra {
		zebraClient := server.NewZebraClient("unix", opts.SocketFile, ldpServer)
		go zebraClient.Serve()
	}

	if !opts.DisableGRPC {
		grpcServer := api.NewGRPCServer(opts.GRPCHosts, ldpServer)
		go grpcServer.Serve()
	}

	ch := make(chan struct{})
	<-ch
}
