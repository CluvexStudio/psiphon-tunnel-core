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
 */

package psiphon

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	socks "github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/goptlib"
)

const (
	socksUDPMaxDatagramSize = 65535

	socksUDPMaxFlowCount = 4096

	socksUDPFlowIdleTimeout = 3 * time.Minute

	socksUDPDNSFlowIdleTimeout = 30 * time.Second
)

// socksUDPAssociation relays datagrams between a SOCKS5 UDP ASSOCIATE client
// and tunneled UDP flows.
//
// Per RFC 1928, the association is bound to the TCP control connection: when
// the control connection closes, the UDP relay terminates and all flows are
// released.
type socksUDPAssociation struct {
	proxy       *SocksProxy
	controlConn *socks.SocksConn
	udpConn     *net.UDPConn

	clientAddrMutex sync.Mutex
	clientAddr      *net.UDPAddr

	flowsMutex  sync.Mutex
	flows       map[string]*socksUDPFlow
	flowsClosed bool

	flowWaitGroup *sync.WaitGroup

	stopOnce   sync.Once
	stopSignal chan struct{}
}

type socksUDPFlow struct {
	conn         net.Conn
	destination  *net.UDPAddr
	idleTimeout  time.Duration
	activityTime time.Time
	activityLock sync.Mutex
}

func (flow *socksUDPFlow) touch() {
	flow.activityLock.Lock()
	defer flow.activityLock.Unlock()
	flow.activityTime = time.Now()
}

func (flow *socksUDPFlow) isIdle() bool {
	flow.activityLock.Lock()
	defer flow.activityLock.Unlock()
	return time.Since(flow.activityTime) >= flow.idleTimeout
}

func (flow *socksUDPFlow) lastActivity() time.Time {
	flow.activityLock.Lock()
	defer flow.activityLock.Unlock()
	return flow.activityTime
}

// handleUDPAssociate services a SOCKS5 UDP ASSOCIATE request. It returns when
// the control connection closes or the relay fails.
func (proxy *SocksProxy) handleUDPAssociate(controlConn *socks.SocksConn) error {

	// The relay must be reachable by the client at the same local address the
	// client used to reach the SOCKS listener. Binding to that address, rather
	// than to a wildcard address, also keeps the relay off any other interface.
	listenIP := net.IPv4(127, 0, 0, 1)
	if localAddr, ok := controlConn.LocalAddr().(*net.TCPAddr); ok && localAddr.IP != nil {
		listenIP = localAddr.IP
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: listenIP, Port: 0})
	if err != nil {
		_ = controlConn.RejectReason(byte(socks.SocksRepGeneralFailure))
		return errors.Trace(err)
	}

	association := &socksUDPAssociation{
		proxy:         proxy,
		controlConn:   controlConn,
		udpConn:       udpConn,
		flows:         make(map[string]*socksUDPFlow),
		flowWaitGroup: new(sync.WaitGroup),
		stopSignal:    make(chan struct{}),
	}

	// A non-wildcard address and port in the request indicates the address the
	// client will send datagrams from. Otherwise the client address is latched
	// from the first datagram received.
	if requestedAddr, err := net.ResolveUDPAddr("udp", controlConn.Req.Target); err == nil &&
		requestedAddr.IP != nil &&
		!requestedAddr.IP.IsUnspecified() &&
		requestedAddr.Port != 0 {
		association.clientAddr = requestedAddr
	}

	defer association.stop()

	err = controlConn.GrantUDPAssociate(udpConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		return errors.Trace(err)
	}

	// RFC 1928: the UDP association terminates with the TCP connection which
	// created it. The control connection carries no further data, so any read
	// result other than blocking means the client is done.
	go func() {
		_, _ = io.Copy(io.Discard, controlConn)
		association.stop()
	}()

	association.relayUpstream()

	return nil
}

func (association *socksUDPAssociation) stop() {
	association.stopOnce.Do(func() {
		close(association.stopSignal)
		_ = association.udpConn.Close()
		_ = association.controlConn.Close()

		association.flowsMutex.Lock()
		association.flowsClosed = true
		flows := make([]*socksUDPFlow, 0, len(association.flows))
		for _, flow := range association.flows {
			flows = append(flows, flow)
		}
		association.flows = make(map[string]*socksUDPFlow)
		association.flowsMutex.Unlock()

		for _, flow := range flows {
			_ = flow.conn.Close()
		}

		association.flowWaitGroup.Wait()
	})
}

func (association *socksUDPAssociation) isStopped() bool {
	select {
	case <-association.stopSignal:
		return true
	default:
		return false
	}
}

func (association *socksUDPAssociation) relayUpstream() {

	buffer := make([]byte, socksUDPMaxDatagramSize)

	for {
		n, sourceAddr, err := association.udpConn.ReadFromUDP(buffer)
		if err != nil {
			if !association.isStopped() {
				NoticeLocalProxyError(_SOCKS_PROXY_TYPE, errors.Trace(err))
			}
			return
		}

		if !association.checkClientAddr(sourceAddr) {
			continue
		}

		host, port, payload, err := socks.DecodeSocks5UDPDatagram(buffer[:n])
		if err != nil {
			continue
		}

		// The udpgw protocol carries only IP addresses. Clients which tunnel
		// packets from a tun device always specify IP addresses.
		ip := net.ParseIP(host)
		if ip == nil {
			continue
		}

		if len(payload) > udpgwMaxPayloadSize {
			continue
		}

		flow, err := association.getFlow(&net.UDPAddr{IP: ip, Port: int(port)})
		if err != nil {
			if association.isStopped() {
				return
			}
			NoticeLocalProxyError(_SOCKS_PROXY_TYPE, errors.Trace(err))
			continue
		}

		flow.touch()

		_, err = flow.conn.Write(payload)
		if err != nil {
			association.removeFlow(flow)
			_ = flow.conn.Close()
			continue
		}
	}
}

func (association *socksUDPAssociation) checkClientAddr(sourceAddr *net.UDPAddr) bool {

	association.clientAddrMutex.Lock()
	defer association.clientAddrMutex.Unlock()

	if association.clientAddr == nil {
		association.clientAddr = sourceAddr
		return true
	}

	return association.clientAddr.Port == sourceAddr.Port &&
		association.clientAddr.IP.Equal(sourceAddr.IP)
}

func (association *socksUDPAssociation) getClientAddr() *net.UDPAddr {
	association.clientAddrMutex.Lock()
	defer association.clientAddrMutex.Unlock()
	return association.clientAddr
}

func (association *socksUDPAssociation) getFlow(
	destination *net.UDPAddr) (*socksUDPFlow, error) {

	key := destination.String()

	association.flowsMutex.Lock()
	if association.flowsClosed {
		association.flowsMutex.Unlock()
		return nil, errors.TraceNew("association is closed")
	}
	flow, ok := association.flows[key]
	association.flowsMutex.Unlock()

	if ok {
		return flow, nil
	}

	association.evictFlows()

	conn, err := association.proxy.tunneler.DialUDP(destination.String())
	if err != nil {
		return nil, errors.Trace(err)
	}

	idleTimeout := socksUDPFlowIdleTimeout
	if destination.Port == udpgwDNSPort {
		idleTimeout = socksUDPDNSFlowIdleTimeout
	}

	flow = &socksUDPFlow{
		conn:         conn,
		destination:  destination,
		idleTimeout:  idleTimeout,
		activityTime: time.Now(),
	}

	association.flowsMutex.Lock()
	if association.flowsClosed {
		association.flowsMutex.Unlock()
		_ = conn.Close()
		return nil, errors.TraceNew("association is closed")
	}
	if existing, ok := association.flows[key]; ok {
		association.flowsMutex.Unlock()
		_ = conn.Close()
		return existing, nil
	}
	association.flows[key] = flow
	association.flowsMutex.Unlock()

	association.flowWaitGroup.Add(1)
	go func() {
		defer association.flowWaitGroup.Done()
		association.relayDownstream(flow)
	}()

	return flow, nil
}

// evictFlows closes the least recently active flow when the flow count is at
// the limit. The udpgw protocol identifies flows with a 16-bit conn ID, so the
// limit also bounds conn ID consumption.
func (association *socksUDPAssociation) evictFlows() {

	association.flowsMutex.Lock()
	if len(association.flows) < socksUDPMaxFlowCount {
		association.flowsMutex.Unlock()
		return
	}
	var oldest *socksUDPFlow
	var oldestKey string
	for key, flow := range association.flows {
		if oldest == nil || flow.lastActivity().Before(oldest.lastActivity()) {
			oldest = flow
			oldestKey = key
		}
	}
	if oldest != nil {
		delete(association.flows, oldestKey)
	}
	association.flowsMutex.Unlock()

	if oldest != nil {
		_ = oldest.conn.Close()
	}
}

func (association *socksUDPAssociation) removeFlow(flow *socksUDPFlow) {
	association.flowsMutex.Lock()
	defer association.flowsMutex.Unlock()
	key := flow.destination.String()
	if association.flows[key] == flow {
		delete(association.flows, key)
	}
}

func (association *socksUDPAssociation) relayDownstream(flow *socksUDPFlow) {

	defer func() {
		association.removeFlow(flow)
		_ = flow.conn.Close()
	}()

	buffer := make([]byte, socksUDPMaxDatagramSize)
	header := make([]byte, 0,
		socks.Socks5UDPHeaderSize+1+net.IPv6len+2+socksUDPMaxDatagramSize)

	for {
		err := flow.conn.SetReadDeadline(time.Now().Add(flow.idleTimeout))
		if err != nil {
			return
		}

		n, err := flow.conn.Read(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if flow.isIdle() {
					return
				}
				continue
			}
			return
		}

		flow.touch()

		clientAddr := association.getClientAddr()
		if clientAddr == nil {
			continue
		}

		datagram, err := socks.EncodeSocks5UDPDatagram(
			header[:0],
			flow.destination.IP,
			uint16(flow.destination.Port),
			buffer[:n])
		if err != nil {
			continue
		}

		_, err = association.udpConn.WriteToUDP(datagram, clientAddr)
		if err != nil {
			if association.isStopped() {
				return
			}
			continue
		}
	}
}
