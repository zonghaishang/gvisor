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

package stack

import (
	"encoding/binary"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/hash/jenkins"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcpconntrack"
)

// Connection tracking is used to track and manipulate packets for NAT rules.
// The connection is created for a packet if it does not exist. Every connection
// contains two tuples (original and reply). The tuples are manipulated if there
// is a matching NAT rule. The packet is modified by looking at the tuples in the
// Prerouting and Output hooks.

// Direction of the tuple.
type ctDirection int

const (
	dirOriginal ctDirection = iota
	dirReply
)

// Status of connection.
// TODO(gvisor.dev/issue/170): Add other states of connection.
type connStatus int

const (
	connNew connStatus = iota
	connEstablished
)

// Manipulation type for the connection.
type manipType int

const (
	manipDstPrerouting manipType = iota
	manipDstOutput
)

const (
	setConnForPacket = iota
	getConnForPacket
)

// connTrackMutable is the manipulatable part of the tuple.
type connTrackMutable struct {
	// addr is source address of the tuple.
	addr tcpip.Address

	// port is source port of the tuple.
	port uint16

	// protocol is network layer protocol.
	protocol tcpip.NetworkProtocolNumber
}

// connTrackImmutable is the non-manipulatable part of the tuple.
type connTrackImmutable struct {
	// addr is destination address of the tuple.
	addr tcpip.Address

	// direction is direction(original or reply) of the tuple.
	direction ctDirection

	// port is destination port of the tuple.
	port uint16

	// protocol is transport layer protocol.
	protocol tcpip.TransportProtocolNumber
}

// connTrackTuple represents the tuple which is created from the
// packet.
type connTrackTuple struct {
	// dst is non-manipulatable part of the tuple.
	dst connTrackImmutable

	// src is manipulatable part of the tuple.
	src connTrackMutable
}

// connTrackTupleHolder is the container of tuple and connection.
type ConnTrackTupleHolder struct {
	// conn is pointer to the connection tracking entry.
	conn *connTrack

	// tuple is original or reply tuple.
	tuple connTrackTuple
}

// connTrack is the connection.
type connTrack struct {
	// originalTupleHolder contains tuple in original direction.
	originalTupleHolder ConnTrackTupleHolder

	// replyTupleHolder contains tuple in reply direction.
	replyTupleHolder ConnTrackTupleHolder

	// status indicates connection is new or established.
	status connStatus

	// timeout indicates the time connection should be active.
	timeout time.Duration

	// manip indicates if the packet should be manipulated.
	manip manipType

	// tcb is TCB control block. It is used to keep track of states
	// of tcp connection.
	tcb tcpconntrack.TCB

	// tcbHook indicates if the packet is inbound or outbound to
	// update the state of tcb.
	tcbHook Hook
}

type ConnTrackTable struct {
	// connMu protects connTrackTable.
	connMu sync.RWMutex

	// connTrackTable maintains a map of tuples needed for connection tracking
	// for iptables NAT rules. The key for the map is an integer calculated
	// using seed, source address, destination address, source port and
	// destination port.
	CtMap map[uint32]ConnTrackTupleHolder

	// seed is a one-time random value initialized at stack startup
	// and is used in calculation of hash key for connection tracking
	// table.
	Seed uint32
}

// parseHeaders sets headers in the packet.
func parseHeaders(pkt PacketBuffer) PacketBuffer {
	newPkt := pkt.Clone()

	// Set network header.
	headerView := newPkt.Data.First()
	netHeader := header.IPv4(headerView)

	hlen := int(netHeader.HeaderLength())
	newPkt.NetworkHeader = headerView[:hlen]
	headerView = headerView[hlen:]

	// TODO(gvisor.dev/issue/170): Need to support for other
	// protocols as well.
	// Set transport header.
	switch protocol := netHeader.TransportProtocol(); protocol {
	case header.UDPProtocolNumber:
		if newPkt.TransportHeader == nil {
			if len(headerView) < header.UDPMinimumSize {
				return newPkt
			}
			newPkt.TransportHeader = buffer.View(header.TCP(headerView))
		}

	case header.TCPProtocolNumber:
		if newPkt.TransportHeader == nil {
			if len(headerView) < header.TCPMinimumSize {
				return newPkt
			}
			newPkt.TransportHeader = buffer.View(header.TCP(headerView))
		}
	}
	return newPkt
}

// packetToTuple converts packet to tuple.
func packetToTuple(pkt PacketBuffer, hook Hook) (connTrackTuple, *tcpip.Error) {
	var tuple connTrackTuple

	netHeader := header.IPv4(pkt.NetworkHeader)
	// TODO(gvisor.dev/issue/170): Need to support for other
	// protocols as well.
	if netHeader == nil || netHeader.TransportProtocol() != header.TCPProtocolNumber {
		return tuple, tcpip.ErrUnknownProtocol
	}
	tcpHeader := header.TCP(pkt.TransportHeader)
	if tcpHeader == nil {
		return tuple, tcpip.ErrUnknownProtocol
	}

	tuple.src.addr = netHeader.SourceAddress()
	tuple.src.port = tcpHeader.SourcePort()
	tuple.src.protocol = header.IPv4ProtocolNumber

	tuple.dst.addr = netHeader.DestinationAddress()
	tuple.dst.port = tcpHeader.DestinationPort()

	// TODO(gvisor.dev/issue/170): Need to support other transport protocols.
	tuple.dst.protocol = header.TCPProtocolNumber
	tuple.dst.direction = dirOriginal

	return tuple, nil
}

// getInvertTuple creates inverted tuple for the given tuple.
func getInvertTuple(tuple connTrackTuple) connTrackTuple {
	var invertTuple connTrackTuple
	invertTuple.src.addr = tuple.dst.addr
	invertTuple.src.port = tuple.dst.port
	invertTuple.src.protocol = header.IPv4ProtocolNumber
	invertTuple.dst.addr = tuple.src.addr
	invertTuple.dst.port = tuple.src.port
	invertTuple.dst.protocol = tuple.dst.protocol
	invertTuple.dst.direction = dirReply
	return invertTuple
}

// makeNewConn creates new connection.
func makeNewConn(tuple, invertTuple connTrackTuple, pkt PacketBuffer) connTrack {
	var conn connTrack
	conn.status = connNew
	conn.originalTupleHolder.tuple = tuple
	conn.originalTupleHolder.conn = &conn
	conn.replyTupleHolder.tuple = invertTuple
	conn.replyTupleHolder.conn = &conn

	return conn
}

// getTupleHash returns hash of the tuple. The fields used for
// generating hash are seed (generated once for stack), source address,
// destination address, source port and destination ports.
func (ct *ConnTrackTable) getTupleHash(tuple connTrackTuple) uint32 {
	h := jenkins.Sum32(ct.Seed)
	h.Write([]byte(tuple.src.addr))
	h.Write([]byte(tuple.dst.addr))
	portBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(portBuf, tuple.src.port)
	h.Write([]byte(portBuf))
	binary.LittleEndian.PutUint16(portBuf, tuple.dst.port)
	h.Write([]byte(portBuf))

	return h.Sum32()
}

// ConnTrackForPacket returns connTrack for packet.
// TODO(gvisor.dev/issue/170): Only TCP packets are supported. Need to support other
// transport protocols.
func (ct *ConnTrackTable) ConnTrackForPacket(pkt PacketBuffer, hook Hook, connType int) (*connTrack, ctDirection) {
	// Headers will not be set in Prerouting.
	// TODO(gvisor.dev/issue/170): Change this after parsing headers code
	// is added.
	var dir ctDirection
	if hook == Prerouting {
		pkt = parseHeaders(pkt)
	}

	tuple, err := packetToTuple(pkt, hook)
	if err != nil {
		return nil, dir
	}

	ct.connMu.Lock()
	defer ct.connMu.Unlock()

	connTrackTable := ct.CtMap
	hash := ct.getTupleHash(tuple)

	var conn *connTrack
	switch connType {
	case setConnForPacket:
		// If connection does not exist for the hash, create a new
		// connection.
		invertTuple := getInvertTuple(tuple)
		replyHash := ct.getTupleHash(invertTuple)
		newConn := makeNewConn(tuple, invertTuple, pkt)
		conn = &newConn

		// Add tupleHolders to the map.
		// TODO(gvisor.dev/issue/170): Need to support collisions using linked list.
		ct.CtMap[hash] = conn.originalTupleHolder
		ct.CtMap[replyHash] = conn.replyTupleHolder

	case getConnForPacket:
		tupleHolder, ok := connTrackTable[hash]
		if !ok {
			return nil, dir
		}

		// If this is the reply of new connection, set the connection
		// status as ESTABLISHED.
		conn = tupleHolder.conn
		if conn.status == connNew && tupleHolder.tuple.dst.direction == dirReply {
			conn.status = connEstablished
		}
		if tupleHolder.conn == nil {
			panic("tupleHolder has null connection tracking entry")
		}

		dir = tupleHolder.tuple.dst.direction
	}
	return conn, dir
}

// SetNatInfo wil manipulate the tuples according to iptables NAT rules.
func (ct *ConnTrackTable) SetNatInfo(pkt PacketBuffer, rt RedirectTarget, hook Hook) {
	conn, _ := ct.ConnTrackForPacket(pkt, hook, getConnForPacket)
	if conn == nil {
		return
	}

	invertTuple := conn.replyTupleHolder.tuple
	replyHash := ct.getTupleHash(invertTuple)

	// TODO(gvisor.dev/issue/170): Support only redirect of ports. Need to
	// support changing of source and destination address.

	// Change the port as per the iptables rule. This tuple will be used
	// to manipulate the packet in HandlePacket.
	if hook == Output {
		addr := []byte{127, 0, 0, 1}
		conn.replyTupleHolder.tuple.src.addr = tcpip.Address(addr[:])
	}

	conn.replyTupleHolder.tuple.src.port = rt.MinPort
	newHash := ct.getTupleHash(conn.replyTupleHolder.tuple)

	// Add the changed tuple to the map.
	ct.connMu.Lock()
	defer ct.connMu.Unlock()
	ct.CtMap[newHash] = conn.replyTupleHolder
	if hook == Output {
		conn.replyTupleHolder.conn.manip = manipDstOutput
	}

	// Delete the old tuple.
	delete(ct.CtMap, replyHash)
}

// handlePacketPrerouting manipulates ports for packets in Prerouting hook.
func handlePacketPrerouting(pkt PacketBuffer, conn *connTrack) {
	tcpHeader := header.TCP(pkt.TransportHeader)

	switch conn.manip {
	case manipDstPrerouting:
		port := conn.replyTupleHolder.tuple.src.port
		tcpHeader.SetDestinationPort(port)
	default:
		port := conn.originalTupleHolder.tuple.dst.port
		tcpHeader.SetSourcePort(port)
	}
}

// handlePacketOutput manipulates ports for packets in Output hook.
func handlePacketOutput(pkt PacketBuffer, conn *connTrack, gso *GSO, r *Route, dir ctDirection) PacketBuffer {
	netHeader := header.IPv4(pkt.NetworkHeader)
	tcpHeader := header.TCP(pkt.TransportHeader)
	addr := []byte{127, 0, 0, 1}

	if conn.manip == manipDstOutput && dir == dirOriginal {
		port := conn.replyTupleHolder.tuple.src.port
		// Change destination address and port.
		tcpHeader.SetDestinationPort(port)
		netHeader.SetDestinationAddress(tcpip.Address(addr[:]))
		log.Infof("change destination address and port")
	} else {
		port := conn.originalTupleHolder.tuple.dst.port
		// Change source address and port.
		tcpHeader.SetSourcePort(port)
		//netHeader.SetSourceAddress(conn.originalTupleHolder.tuple.dst.addr)
		log.Infof("change source address and port")
	}

	// Calculate the TCP checksum and set it.
	tcpHeader.SetChecksum(0)
	hdr := &pkt.Header
	length := uint16(pkt.Data.Size()+hdr.UsedLength()) - uint16(netHeader.HeaderLength())
	xsum := r.PseudoHeaderChecksum(header.TCPProtocolNumber, length)
	if gso != nil && gso.NeedsCsum {
		tcpHeader.SetChecksum(xsum)
	} else if r.Capabilities()&CapabilityTXChecksumOffload == 0 {
		xsum = header.ChecksumVVWithOffset(pkt.Data, xsum, int(tcpHeader.DataOffset()), pkt.Data.Size())
		tcpHeader.SetChecksum(^tcpHeader.CalculateChecksum(xsum))
	}

	netHeader.SetChecksum(^netHeader.CalculateChecksum())

	return pkt
}

// HandlePacket will manipulate the packet's ports if the connection and
// iptables rule exists.
func (ct *ConnTrackTable) HandlePacket(pkt PacketBuffer, hook Hook, gso *GSO, r *Route, natDone *bool) bool {
	if hook != Prerouting && hook != Output {
		return false
	}

	conn, dir := ct.ConnTrackForPacket(pkt, hook, getConnForPacket)
	// Connection or Rule not found for the packet.
	if conn == nil {
		return false
	}

	if hook == Prerouting {
		// Headers will not be set in Prerouting.
		// TODO(gvisor.dev/issue/170): Change this after parsing headers code
		// is added.
		pkt = parseHeaders(pkt)
	}

	netHeader := header.IPv4(pkt.NetworkHeader)
	// TODO(gvisor.dev/issue/170): Need to support for other transport
	// protocols as well.
	if netHeader == nil || netHeader.TransportProtocol() != header.TCPProtocolNumber {
		return false
	}

	tcpHeader := header.TCP(pkt.TransportHeader)
	if tcpHeader == nil {
		return false
	}

	switch hook {
	case Prerouting:
		handlePacketPrerouting(pkt, conn)
	case Output:
		pkt = handlePacketOutput(pkt, conn, gso, r, dir)
		*natDone = true
	}

	// Update the state of tcb.
	// TODO(gvisor.dev/issue/170): Add support in tcpcontrack to handle
	// other tcp states.
	var st tcpconntrack.Result
	if conn.tcb.IsEmpty() {
		conn.tcb.Init(tcpHeader)
		conn.tcbHook = hook
	} else {
		switch hook {
		case conn.tcbHook:
			st = conn.tcb.UpdateStateOutbound(tcpHeader)
		default:
			st = conn.tcb.UpdateStateInbound(tcpHeader)
		}
	}

	// Delete conntrack if tcp connection is closed.
	if st == tcpconntrack.ResultClosedByPeer || st == tcpconntrack.ResultClosedBySelf || st == tcpconntrack.ResultReset {
		ct.DeleteConnTrack(conn)
	}

	return true
}

// DeleteConnTrack deletes the connection.
func (ct *ConnTrackTable) DeleteConnTrack(conn *connTrack) {
	if conn == nil {
		return
	}

	tuple := conn.originalTupleHolder.tuple
	hash := ct.getTupleHash(tuple)
	invertTuple := conn.replyTupleHolder.tuple
	replyHash := ct.getTupleHash(invertTuple)

	ct.connMu.Lock()
	defer ct.connMu.Unlock()

	delete(ct.CtMap, hash)
	delete(ct.CtMap, replyHash)
}
