// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package udp_icmp_error_propagation_test

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	tb "gvisor.dev/gvisor/test/packetimpact/testbench"
)

type connected bool

func (c connected) String() string {
	if c {
		return "Connected"
	}
	return "Connectionless"
}

type icmpError int

const (
	portUnreachable icmpError = iota
	timeToLiveExceeded
)

func (e icmpError) String() string {
	switch e {
	case portUnreachable:
		return "PortUnreachable"
	case timeToLiveExceeded:
		return "TimeToLiveExpired"
	}
	return "Unknown ICMP error"
}

func (e icmpError) ToICMPv4() *tb.ICMPv4 {
	switch e {
	case portUnreachable:
		return &tb.ICMPv4{Type: tb.ICMPv4Type(header.ICMPv4DstUnreachable), Code: tb.Uint8(header.ICMPv4PortUnreachable)}
	case timeToLiveExceeded:
		return &tb.ICMPv4{Type: tb.ICMPv4Type(header.ICMPv4TimeExceeded), Code: tb.Uint8(header.ICMPv4TTLExceeded)}
	}
	return nil
}

type testFunc func(*testing.T, *tb.DUT, *tb.UDPIPv4, int32, syscall.Errno)

// testRecv tests observing the ICMP error through the recv syscall.
// A packet is sent to the DUT, and if wantErrno is non-zero, then the first
// recv should fail and the second should succeed. Otherwise if wantErrno is
// zero then the first recv should succeed immediately.
func testRecv(t *testing.T, dut *tb.DUT, conn *tb.UDPIPv4, remoteFd int32, wantErrno syscall.Errno) {
	conn.Send(tb.UDP{})

	if wantErrno != syscall.Errno(0) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		ret, _, err := dut.RecvWithErrno(ctx, remoteFd, 100, 0)
		if ret != -1 {
			t.Fatalf("recv after ICMP error succeeded unexpectedly")
		}
		if err != wantErrno {
			t.Fatalf("recv after ICMP error resulted in error (%[1]d) %[1]v, expected (%[2]d) %[2]v", err, wantErrno)
		}
	}

	dut.Recv(remoteFd, 100, 0)
}

// testSendTo tests observing the ICMP error through the send syscall.
// If wantErrno is non-zero, the first send should fail and a subsequent send
// should suceed; while if wantErrno is zero then the first send should just
// succeed.
func testSendTo(t *testing.T, dut *tb.DUT, conn *tb.UDPIPv4, remoteFd int32, wantErrno syscall.Errno) {
	if wantErrno != syscall.Errno(0) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		ret, err := dut.SendToWithErrno(ctx, remoteFd, nil, 0, conn.LocalAddr())

		if ret != -1 {
			t.Fatalf("sendto after ICMP error succeeded unexpectedly")
		}
		if err != wantErrno {
			t.Fatalf("sendto after ICMP error resulted in error (%[1]d) %[1]v, expected (%[2]d) %[2]v", err, wantErrno)
		}
	}

	dut.SendTo(remoteFd, nil, 0, conn.LocalAddr())
	if _, err := conn.Expect(tb.UDP{}, time.Second); err != nil {
		t.Fatalf("did not receive UDP packet as expected: %s", err)
	}
}

func testSockOpt(t *testing.T, dut *tb.DUT, conn *tb.UDPIPv4, remoteFd int32, wantErrno syscall.Errno) {
	errno := syscall.Errno(dut.GetSockOptInt(remoteFd, unix.SOL_SOCKET, unix.SO_ERROR))
	if errno != wantErrno {
		t.Fatalf("SO_ERROR sockopt after ICMP error is (%[1]d) %[1]v, expected (%[2]d) %[2]v", errno, wantErrno)
	}

	// Check that after clearing socket error, sending doesn't fail.
	dut.SendTo(remoteFd, nil, 0, conn.LocalAddr())
	if _, err := conn.Expect(tb.UDP{}, time.Second); err != nil {
		t.Fatalf("did not receive UDP packet as expected: %s", err)
	}
}

func test(t *testing.T, c connected, i icmpError, e syscall.Errno, f testFunc) {
	dut := tb.NewDUT(t)
	defer dut.TearDown()

	remoteFd, remotePort := dut.CreateBoundSocket(unix.SOCK_DGRAM, unix.IPPROTO_UDP, net.ParseIP("0.0.0.0"))
	defer dut.Close(remoteFd)

	conn := tb.NewUDPIPv4(t, tb.UDP{DstPort: &remotePort}, tb.UDP{SrcPort: &remotePort})
	defer conn.Close()

	if c {
		dut.Connect(remoteFd, conn.LocalAddr())
	}

	dut.SendTo(remoteFd, nil, 0, conn.LocalAddr())
	udp, err := conn.Expect(tb.UDP{}, time.Second)
	if err != nil {
		t.Fatalf("did not receive message from DUT: %s", err)
	}

	if i == timeToLiveExceeded {
		ip, ok := udp.Prev().(*tb.IPv4)
		if !ok {
			t.Fatalf("expected %s to be IPv4", udp.Prev())
		}
		*ip.TTL = 1
		// Let serialization recalculate the checksum since we set the
		// TTL to 1.
		ip.Checksum = nil

		// Note that the ICMP payload is valid in this case because the UDP
		// payload is empty. If the UDP payload were not empty, the packet
		// length during serialization may not be calculated correctly,
		// resulting in a mal-formed packet.
		conn.SendIP(i.ToICMPv4(), ip, udp)
	} else {
		conn.SendIP(i.ToICMPv4(), udp.Prev(), udp)
	}

	f(t, &dut, &conn, remoteFd, e)
}

// TestUdpIcmpErrorPropagation tests that ICMP PortUnreachable error messages
// destined for a "connected" UDP socket are observable on said socket by:
// 1. causing the next send to fail with ECONNREFUSED,
// 2. causing the next recv to fail with ECONNREFUSED, or
// 3. returning ECONNREFUSED through the SO_ERROR socket option.
func TestUdpIcmpErrorPropagation(t *testing.T) {
	for _, c := range []connected{true, false} {
		t.Run(fmt.Sprint(c), func(t *testing.T) {
			for _, i := range []icmpError{portUnreachable, timeToLiveExceeded} {
				t.Run(fmt.Sprint(i), func(t *testing.T) {
					wantErrno := syscall.Errno(0)
					if c && i == portUnreachable {
						wantErrno = unix.ECONNREFUSED
					}
					for _, tt := range []struct {
						name string
						f    testFunc
					}{
						{"SendTo", testSendTo},
						{"Recv", testRecv},
						{"SockOpt", testSockOpt},
					} {
						t.Run(tt.name, func(t *testing.T) {
							test(t, c, i, wantErrno, tt.f)
						})
					}
				})
			}
		})
	}
}
