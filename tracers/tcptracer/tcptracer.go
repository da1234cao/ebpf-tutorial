//go:build linux

package tcptracer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target native tcptracer tcptracer.bpf.c -- -I../

var nativeEndian binary.ByteOrder

func init() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		panic("Could not determine native endianness.")
	}
}

func Ntohs(x uint16) uint16 {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, x)
	return nativeEndian.Uint16(data)
}

func handleEvents(objs *tcptracerObjects) (err error) {
	eventsReader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Println("failed to create ringbuf reader:", err)
		return nil
	}
	defer eventsReader.Close()

	type tcpTracerEvent struct {
		// Union for saddr
		SaddrV4 [4]byte  // IPv4 address
		_       [12]byte // padding to match 16-byte IPv6 (128-bit) size

		// Union for daddr
		DaddrV4 [4]byte  // IPv4 address
		_       [12]byte // padding to match 16-byte IPv6 (128-bit) size

		Task  [16]byte // TASK_COMM_LEN = 16
		TsUs  uint64   // timestamp in microseconds
		Af    uint32   // AF_INET / AF_INET6
		Pid   uint32
		Uid   uint32
		Netns uint32
		Dport uint16
		Sport uint16
		Type  uint8
		_     uint8 // explicit padding if needed
	}

	for {
		record, err := eventsReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			log.Println("failed to read ringbuf: ", err)
			continue
		}

		var event tcpTracerEvent
		if err = binary.Read(bytes.NewBuffer(record.RawSample), nativeEndian, &event); err != nil {
			log.Println("failed to parse ringbuf event: ", err)
			continue
		}

		log.Printf("Command: %s, "+
			"Source Address: %s, "+
			"Destination Address: %s, "+
			"Source Port: %d, "+
			"Destination Port: %d",
			unix.ByteSliceToString(event.Task[:]),
			net.IP(event.SaddrV4[:]).String(),
			net.IP(event.DaddrV4[:]).String(),
			Ntohs(event.Sport),
			Ntohs(event.Dport))
	}
}

func StartTrace() (err error) {
	objs := tcptracerObjects{}
	if err := loadTcptracerObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	links := make(map[string]*link.Link)

	kprobePorg := make(map[string]*ebpf.Program)
	kprobePorg["tcp_v4_connect"] = objs.TcpV4Connect
	kprobePorg["tcp_v6_connect"] = objs.TcpV6Connect
	kprobePorg["tcp_close"] = objs.EntryTraceClose
	kprobePorg["tcp_set_state"] = objs.EnterTcpSetState

	for name, prog := range kprobePorg {
		l, err := link.Kprobe(name, prog, nil)
		if err != nil {
			log.Printf("failed to attach %s: %v", name, err)
			return err
		}
		links[name] = &l
		log.Printf("attached %s", name)
	}

	kretprobePorg := make(map[string]*ebpf.Program)
	kretprobePorg["tcp_v4_connect"] = objs.TcpV4ConnectRet
	kretprobePorg["tcp_v6_connect"] = objs.TcpV6ConnectRet
	kretprobePorg["inet_csk_accept"] = objs.ExitInetCskAccept

	for name, prog := range kretprobePorg {
		l, err := link.Kretprobe(name, prog, nil)
		if err != nil {
			log.Printf("failed to attach %s: %v", name, err)
			return err
		}
		links[name] = &l
		log.Printf("attached kret %s", name)
	}

	defer func() {
		for name, l := range links {
			if l != nil {
				(*l).Close()
				log.Printf("detached %s", name)
			}
		}
	}()

	handleEvents(&objs)
	return
}
