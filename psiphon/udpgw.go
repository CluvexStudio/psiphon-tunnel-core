/*
 * Copyright (c) 2026, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The udpgw protocol and original client and server implementations:
 * Copyright (c) 2009, Ambroz Bizjak <ambrop7@gmail.com>
 * https://github.com/ambrop72/badvpn
 *
 */

package psiphon

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

const UDPGWServerAddress = "127.0.0.1:7300"

const (
	udpgwFlagKeepalive = 1 << 0
	udpgwFlagRebind    = 1 << 1
	udpgwFlagDNS       = 1 << 2
	udpgwFlagIPv6      = 1 << 3

	udpgwMaxPreambleSize = 23
	udpgwMaxPayloadSize  = 32768
	udpgwMaxMessageSize  = udpgwMaxPreambleSize + udpgwMaxPayloadSize

	udpgwFlowPacketQueueSize = 32

	udpgwDNSPort = 53
)

type udpgwClient struct {
	conn           net.Conn
	transparentDNS bool

	writeMutex  sync.Mutex
	writeBuffer []byte

	mutex      sync.Mutex
	flows      map[uint16]*udpgwFlow
	nextConnID uint16
	closed     bool

	closedSignal chan struct{}
	readLoopDone chan struct{}
}

func newUDPGWClient(conn net.Conn, transparentDNS bool) *udpgwClient {

	client := &udpgwClient{
		conn:           conn,
		transparentDNS: transparentDNS,
		writeBuffer:    make([]byte, udpgwMaxMessageSize),
		flows:          make(map[uint16]*udpgwFlow),
		closedSignal:   make(chan struct{}),
		readLoopDone:   make(chan struct{}),
	}

	go client.readLoop()

	return client
}

func (client *udpgwClient) IsClosed() bool {
	select {
	case <-client.closedSignal:
		return true
	default:
		return false
	}
}

func (client *udpgwClient) Close() error {

	client.mutex.Lock()
	if client.closed {
		client.mutex.Unlock()
		return nil
	}
	client.closed = true
	flows := make([]*udpgwFlow, 0, len(client.flows))
	for _, flow := range client.flows {
		flows = append(flows, flow)
	}
	client.flows = make(map[uint16]*udpgwFlow)
	client.mutex.Unlock()

	close(client.closedSignal)
	err := client.conn.Close()

	for _, flow := range flows {
		flow.signalClosed()
	}

	<-client.readLoopDone

	return err
}

func (client *udpgwClient) OpenFlow(
	remoteIP net.IP, remotePort uint16) (*udpgwFlow, error) {

	if remoteIP.To4() == nil && remoteIP.To16() == nil {
		return nil, errors.TraceNew("invalid udpgw remote IP")
	}

	client.mutex.Lock()
	defer client.mutex.Unlock()

	if client.closed {
		return nil, errors.TraceNew("udpgw client is closed")
	}

	connID := client.nextConnID
	allocated := false
	for i := 0; i <= 0xffff; i++ {
		if _, ok := client.flows[connID]; !ok {
			allocated = true
			break
		}
		connID++
	}
	if !allocated {
		return nil, errors.TraceNew("no available udpgw conn ID")
	}
	client.nextConnID = connID + 1

	flow := &udpgwFlow{
		client:     client,
		connID:     connID,
		remoteIP:   remoteIP,
		remotePort: remotePort,
		dns:        client.transparentDNS && remotePort == udpgwDNSPort,
		packets:    make(chan []byte, udpgwFlowPacketQueueSize),
		closed:     make(chan struct{}),
		firstWrite: true,
	}
	client.flows[connID] = flow

	return flow, nil
}

func (client *udpgwClient) removeFlow(flow *udpgwFlow) {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if client.flows[flow.connID] == flow {
		delete(client.flows, flow.connID)
	}
}

func (client *udpgwClient) writePacket(
	connID uint16,
	remoteIP net.IP,
	remotePort uint16,
	dns bool,
	rebind bool,
	payload []byte) error {

	if len(payload) > udpgwMaxPayloadSize {
		return errors.TraceNew("udpgw payload exceeds maximum size")
	}

	var flags uint8
	addr := remoteIP.To4()
	if addr == nil {
		addr = remoteIP.To16()
		if addr == nil {
			return errors.TraceNew("invalid udpgw remote IP")
		}
		flags |= udpgwFlagIPv6
	}
	if dns {
		flags |= udpgwFlagDNS
	}
	if rebind {
		flags |= udpgwFlagRebind
	}

	preambleSize := 7 + len(addr)

	client.writeMutex.Lock()
	defer client.writeMutex.Unlock()

	if client.IsClosed() {
		return errors.TraceNew("udpgw client is closed")
	}

	buffer := client.writeBuffer
	binary.LittleEndian.PutUint16(
		buffer[0:2], uint16(preambleSize-2)+uint16(len(payload)))
	buffer[2] = flags
	binary.LittleEndian.PutUint16(buffer[3:5], connID)
	copy(buffer[5:5+len(addr)], addr)
	binary.BigEndian.PutUint16(
		buffer[5+len(addr):preambleSize], remotePort)
	copy(buffer[preambleSize:], payload)

	_, err := client.conn.Write(buffer[0 : preambleSize+len(payload)])
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func (client *udpgwClient) readLoop() {

	defer close(client.readLoopDone)

	buffer := make([]byte, udpgwMaxMessageSize)

	for {
		connID, remoteIP, remotePort, payload, keepalive, err := readUDPGWMessage(
			client.conn, buffer)
		if err != nil {
			if err != io.EOF && !client.IsClosed() {
				NoticeWarning("udpgw read failed: %v", errors.Trace(err))
			}
			break
		}
		if keepalive {
			continue
		}

		client.mutex.Lock()
		flow := client.flows[connID]
		client.mutex.Unlock()

		if flow == nil {
			continue
		}

		if flow.remotePort != remotePort || !flow.remoteIP.Equal(remoteIP) {
			continue
		}

		packet := make([]byte, len(payload))
		copy(packet, payload)

		select {
		case flow.packets <- packet:
		case <-flow.closed:
		default:
		}
	}

	client.mutex.Lock()
	flows := make([]*udpgwFlow, 0, len(client.flows))
	for _, flow := range client.flows {
		flows = append(flows, flow)
	}
	client.mutex.Unlock()

	for _, flow := range flows {
		flow.signalClosed()
	}
}

func readUDPGWMessage(reader io.Reader, buffer []byte) (
	connID uint16,
	remoteIP net.IP,
	remotePort uint16,
	payload []byte,
	keepalive bool,
	err error) {

	_, err = io.ReadFull(reader, buffer[0:2])
	if err != nil {
		if err != io.EOF {
			err = errors.Trace(err)
		}
		return 0, nil, 0, nil, false, err
	}

	size := binary.LittleEndian.Uint16(buffer[0:2])
	if size < 3 || int(size) > len(buffer)-2 {
		return 0, nil, 0, nil, false, errors.TraceNew("invalid udpgw message size")
	}

	_, err = io.ReadFull(reader, buffer[2:2+size])
	if err != nil {
		if err != io.EOF {
			err = errors.Trace(err)
		}
		return 0, nil, 0, nil, false, err
	}

	flags := buffer[2]
	connID = binary.LittleEndian.Uint16(buffer[3:5])

	if flags&udpgwFlagKeepalive != 0 {
		return connID, nil, 0, nil, true, nil
	}

	var packetStart, packetEnd int
	if flags&udpgwFlagIPv6 != 0 {
		if size < 21 {
			return 0, nil, 0, nil, false, errors.TraceNew("invalid udpgw message size")
		}
		remoteIP = make(net.IP, net.IPv6len)
		copy(remoteIP, buffer[5:21])
		remotePort = binary.BigEndian.Uint16(buffer[21:23])
		packetStart = 23
		packetEnd = 23 + int(size) - 21
	} else {
		if size < 9 {
			return 0, nil, 0, nil, false, errors.TraceNew("invalid udpgw message size")
		}
		remoteIP = make(net.IP, net.IPv4len)
		copy(remoteIP, buffer[5:9])
		remotePort = binary.BigEndian.Uint16(buffer[9:11])
		packetStart = 11
		packetEnd = 11 + int(size) - 9
	}

	return connID, remoteIP, remotePort, buffer[packetStart:packetEnd], false, nil
}

type udpgwFlow struct {
	client     *udpgwClient
	connID     uint16
	remoteIP   net.IP
	remotePort uint16
	dns        bool

	packets chan []byte

	writeMutex sync.Mutex
	firstWrite bool

	closeOnce sync.Once
	closed    chan struct{}

	readDeadline udpgwDeadline
}

func (flow *udpgwFlow) WritePacket(payload []byte) error {

	select {
	case <-flow.closed:
		return errors.TraceNew("udpgw flow is closed")
	default:
	}

	flow.writeMutex.Lock()
	rebind := flow.firstWrite
	flow.firstWrite = false
	flow.writeMutex.Unlock()

	err := flow.client.writePacket(
		flow.connID,
		flow.remoteIP,
		flow.remotePort,
		flow.dns,
		rebind,
		payload)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func (flow *udpgwFlow) ReadPacket() ([]byte, error) {

	var timeout <-chan time.Time
	if deadline, ok := flow.readDeadline.get(); ok {
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		timeout = timer.C
	}

	select {
	case packet := <-flow.packets:
		return packet, nil
	case <-flow.closed:
		return nil, errors.TraceNew("udpgw flow is closed")
	case <-timeout:
		return nil, errUDPGWTimeout
	}
}

func (flow *udpgwFlow) signalClosed() {
	flow.closeOnce.Do(func() { close(flow.closed) })
}

func (flow *udpgwFlow) Close() error {
	flow.signalClosed()
	flow.client.removeFlow(flow)
	return nil
}

var errUDPGWTimeout error = &udpgwTimeoutError{}

type udpgwTimeoutError struct{}

func (e *udpgwTimeoutError) Error() string   { return "udpgw i/o timeout" }
func (e *udpgwTimeoutError) Timeout() bool   { return true }
func (e *udpgwTimeoutError) Temporary() bool { return true }

type udpgwDeadline struct {
	mutex    sync.Mutex
	deadline time.Time
}

func (d *udpgwDeadline) set(deadline time.Time) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.deadline = deadline
}

func (d *udpgwDeadline) get() (time.Time, bool) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return d.deadline, !d.deadline.IsZero()
}

type udpgwConn struct {
	flow *udpgwFlow
}

func newUDPGWConn(flow *udpgwFlow) *udpgwConn {
	return &udpgwConn{flow: flow}
}

func (conn *udpgwConn) Read(b []byte) (int, error) {
	packet, err := conn.flow.ReadPacket()
	if err != nil {
		return 0, err
	}
	return copy(b, packet), nil
}

func (conn *udpgwConn) Write(b []byte) (int, error) {
	err := conn.flow.WritePacket(b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (conn *udpgwConn) Close() error {
	return conn.flow.Close()
}

func (conn *udpgwConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
}

func (conn *udpgwConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{
		IP:   conn.flow.remoteIP,
		Port: int(conn.flow.remotePort),
	}
}

func (conn *udpgwConn) SetDeadline(t time.Time) error {
	return conn.SetReadDeadline(t)
}

func (conn *udpgwConn) SetReadDeadline(t time.Time) error {
	conn.flow.readDeadline.set(t)
	return nil
}

func (conn *udpgwConn) SetWriteDeadline(t time.Time) error {
	return nil
}
