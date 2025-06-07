package config

import "flag"

type Config struct {
	TcpTracer bool
}

var GlobalConfig Config

func init() {
	flag.BoolVar(&GlobalConfig.TcpTracer, "tcp", true, "tcp tracer")
}
