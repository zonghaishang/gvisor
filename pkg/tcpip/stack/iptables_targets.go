// Copyright 2019 The gVisor Authors.
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

package stack

import (
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// AcceptTarget accepts packets.
type AcceptTarget struct{}

// Action implements Target.Action.
func (AcceptTarget) Action(PacketBuffer, *ConnTrackTable, Hook, *GSO, *Route) (RuleVerdict, int) {
	return RuleAccept, 0
}

// DropTarget drops packets.
type DropTarget struct{}

// Action implements Target.Action.
func (DropTarget) Action(PacketBuffer, *ConnTrackTable, Hook, *GSO, *Route) (RuleVerdict, int) {
	return RuleDrop, 0
}

// ErrorTarget logs an error and drops the packet. It represents a target that
// should be unreachable.
type ErrorTarget struct{}

// Action implements Target.Action.
func (ErrorTarget) Action(PacketBuffer, *ConnTrackTable, Hook, *GSO, *Route) (RuleVerdict, int) {
	log.Debugf("ErrorTarget triggered.")
	return RuleDrop, 0
}

// UserChainTarget marks a rule as the beginning of a user chain.
type UserChainTarget struct {
	Name string
}

// Action implements Target.Action.
func (UserChainTarget) Action(PacketBuffer, *ConnTrackTable, Hook, *GSO, *Route) (RuleVerdict, int) {
	panic("UserChainTarget should never be called.")
}

// ReturnTarget returns from the current chain. If the chain is a built-in, the
// hook's underflow should be called.
type ReturnTarget struct{}

// Action implements Target.Action.
func (ReturnTarget) Action(PacketBuffer, *ConnTrackTable, Hook, *GSO, *Route) (RuleVerdict, int) {
	return RuleReturn, 0
}

// RedirectTarget redirects the packet by modifying the destination port/IP.
// Min and Max values for IP and Ports in the struct indicate the range of
// values which can be used to redirect.
type RedirectTarget struct {
	// TODO(gvisor.dev/issue/170): Other flags need to be added after
	// we support them.
	// RangeProtoSpecified flag indicates single port is specified to
	// redirect.
	RangeProtoSpecified bool

	// Min address used to redirect.
	MinIP tcpip.Address

	// Max address used to redirect.
	MaxIP tcpip.Address

	// Min port used to redirect.
	MinPort uint16

	// Max port used to redirect.
	MaxPort uint16
}

// Action implements Target.Action.
// TODO(gvisor.dev/issue/170): Parse headers without copying. The current
// implementation works for PREROUTING and OUTPUT hooks. It calls pkt.Clone()
// which should not be the case.
func (rt RedirectTarget) Action(pkt PacketBuffer, ct *ConnTrackTable, hook Hook, gso *GSO, r *Route) (RuleVerdict, int) {
	if hook == Prerouting {
		pkt = parseHeaders(pkt)
	}

	log.Infof("Redirect target reached")
	netHeader := header.IPv4(pkt.NetworkHeader)

	// TODO(gvisor.dev/issue/170): Change destination address to
	// loopback or interface address on which the packet was
	// received.

	// TODO(gvisor.dev/issue/170): Check Flags in RedirectTarget if
	// we need to change dest address (for OUTPUT chain) or ports.
	switch protocol := netHeader.TransportProtocol(); protocol {
	case header.UDPProtocolNumber:
		udpHeader := header.UDP(pkt.TransportHeader)
		udpHeader.SetDestinationPort(rt.MinPort)

		// Calculate UDP checksum and set it.
		if hook == Output {
			udpHeader.SetChecksum(0)
			hdr := &pkt.Header
			length := uint16(pkt.Data.Size()+hdr.UsedLength()) - uint16(netHeader.HeaderLength())

			// Only calculate the checksum if offloading isn't supported.
			if r.Capabilities()&CapabilityTXChecksumOffload == 0 {
				xsum := r.PseudoHeaderChecksum(protocol, length)
				for _, v := range pkt.Data.Views() {
					xsum = header.Checksum(v, xsum)
				}
				udpHeader.SetChecksum(^udpHeader.CalculateChecksum(xsum))
			}

			// Change destination address.
			addr := []byte{127, 0, 0, 1}
			netHeader.SetDestinationAddress(tcpip.Address(addr[:]))
			netHeader.SetChecksum(^netHeader.CalculateChecksum())

			// Handle packets locally.
			r.Loop = PacketLoop
		}
	case header.TCPProtocolNumber:
		if ct == nil {
			return RuleAccept, 0
		}

		// Set up conection for matching NAT rule.
		// Only the first packet of the connection comes here.
		// Other packets will be manipulated in connection tracking.
		if conn, _ := ct.ConnTrackForPacket(pkt, hook, getConnForPacket); conn == nil {
			ct.ConnTrackForPacket(pkt, hook, setConnForPacket)
		}
		ct.SetNatInfo(pkt, rt, hook)

	default:
		return RuleDrop, 0
	}

	return RuleAccept, 0
}
