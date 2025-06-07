package main

import (
	"flag"
	"log"
	"os"

	"github.com/da1234cao/ebpf-tutorial/tracers/config"
	"github.com/da1234cao/ebpf-tutorial/tracers/tcptracer"
)

func main() {
	log.SetOutput(os.Stdout)
	log.Println("Starting...")
	flag.Parse()
	log.Println("TcpTracer:", config.GlobalConfig.TcpTracer)

	tcptracer.StartTrace()
}
