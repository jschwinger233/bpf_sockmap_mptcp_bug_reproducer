package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	_ "net/http/pprof"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/jschwinger233/aws_k8s_sockmap_crash_reproducer/bpf"
)

func ntohl4(u uint32) net.IP {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], u)
	return net.IP(b[:])
}

func init() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock: %v", err)
	}
}

func main() {
	spec, err := bpf.LoadBpf()
	if err != nil {
		log.Fatalf("failed to load BPF: %v", err)
	}

	objs := bpf.BpfObjects{}
	opts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
		},
	}
	if err = spec.LoadAndAssign(&objs, &opts); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Verifier log:\n%+v\n", ve)
		}
		log.Fatalf("failed to load BPF objects: %v", err)
	}
	defer objs.Close()
	log.Printf("BPF objects loaded successfully")

	cgroupPath := "/sys/fs/cgroup/"
	cg, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: objs.SockopsTcpLifetime,
	})
	if err != nil {
		log.Fatalf("AttachCgroup: %v: %v", objs.SockopsTcpLifetime.String(), err)
	}
	defer cg.Close()

	for _, prog := range []*ebpf.Program{
		objs.FexitSysAccept4,
		objs.FexitSysAccept,
	} {
		fp, err := link.AttachTracing(link.TracingOptions{
			Program:    prog,
			AttachType: ebpf.AttachTraceFExit,
		})
		if err != nil {
			fmt.Printf("link.AttachTracing recvfrom: %v", err)
			return
		}
		defer fp.Close()
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("open ringbuf: %v", err)
	}
	defer rd.Close()

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			log.Fatalf("ringbuf read: %v", err)
		}

		var ev bpf.BpfEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			log.Printf("decode: %v", err)
			continue
		}

		switch ev.Op {
		case 5: // PASSIVE_ESTABLISHED

			fmt.Printf("Passive established: sk=0x%x %s:%d -> %s:%d\n", ev.Sk,
				ntohl4(ev.RemoteIp4), ev.RemotePort,
				ntohl4(ev.LocalIp4), ev.LocalPort)
		case 0xff: // sys accept
			fmt.Printf("sys_accept: pid=%d comm=%s sk=0x%x %s:%d -> %s:%d\n", ev.Pid, ev.Pname, ev.Sk,
				ntohl4(ev.RemoteIp4), ev.RemotePort,
				ntohl4(ev.LocalIp4), ev.LocalPort)

		}
	}
}

type bytesReader []byte

func (b bytesReader) Read(p []byte) (int, error) {
	n := copy(p, b)
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
