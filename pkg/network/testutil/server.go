// +build linux

package testutil

import (
	"fmt"
	"io"
	"net"
	"testing"

	"inet.af/netaddr"

	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netns"
)

// StartServerTCPNs is identical to StartServerTCP, but it operates with the
// network namespace provided by name.
func StartServerTCPNs(t *testing.T, ip netaddr.IP, port int, ns string) io.Closer {
	h, err := netns.GetFromName(ns)
	require.NoError(t, err)

	var closer io.Closer
	_ = util.WithNS("/proc", h, func() error {
		closer = StartServerTCP(t, ip, port)
		return nil
	})

	return closer
}

// StartServerTCP starts a TCP server listening at provided IP address and port.
// It will respond to any connection with "hello" and then close the connection.
// It returns an io.Closer that should be Close'd when you are finished with it.
func StartServerTCP(t *testing.T, ip netaddr.IP, port int) io.Closer {
	ch := make(chan struct{})
	addr := fmt.Sprintf("%s:%d", ip, port)
	network := "tcp"
	if ip.Is6() {
		network = "tcp6"
		addr = fmt.Sprintf("[%s]:%d", ip, port)
	}

	l, err := net.Listen(network, addr)
	require.NoError(t, err)
	go func() {
		close(ch)
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}

			_, _ = conn.Write([]byte("hello"))
			conn.Close()
		}
	}()
	<-ch

	return l
}

// StartServerUDPNs is identical to StartServerUDP, but it operates with the
// network namespace provided by name.
func StartServerUDPNs(t *testing.T, ip netaddr.IP, port uint16, ns string) io.Closer {
	h, err := netns.GetFromName(ns)
	require.NoError(t, err)

	var closer io.Closer
	_ = util.WithNS("/proc", h, func() error {
		closer = StartServerUDP(t, ip, port)
		return nil
	})

	return closer
}

// StartServerUDP starts a UDP server listening at provided IP address and port.
// It does not respond in any fashion to sent datagrams.
// It returns an io.Closer that should be Close'd when you are finished with it.
func StartServerUDP(t *testing.T, ip netaddr.IP, port uint16) io.Closer {
	ch := make(chan struct{})
	network := "udp"
	if ip.Is6() {
		network = "udp6"
	}

	l, err := net.ListenUDP(network, netaddr.IPPortFrom(ip, port).UDPAddr())
	require.NoError(t, err)
	go func() {
		close(ch)

		for {
			bs := make([]byte, 10)
			_, err := l.Read(bs)
			if err != nil {
				return
			}
		}
	}()
	<-ch

	return l
}
