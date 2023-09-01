package stgutg

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"tglib"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/ishidawataru/sctp"
	"golang.org/x/net/ipv4"
)

// Needed to assert that no two NGAP exchanges happen at the same time
var ngapMutex *sync.Mutex

var shutdownStarted atomic.Bool

type StateCode uint8

const (
	CodeRecvDiscover StateCode = iota
	CodeSentOffer    StateCode = iota
	CodeRecvRequest  StateCode = iota
	CodeSentAck      StateCode = iota
	CodeRecvRelease  StateCode = iota
	CodeReleased     StateCode = iota
)

type ClientInfo struct {
	IP                 net.IP
	UE                 *tglib.RanUeContext
	PDU                []byte
	TEID               uint32
	UPFAddr            *syscall.SockaddrInet4
	State              StateCode
	SessionEstablished bool
}

type Clients struct {
	Value map[[6]byte]ClientInfo
	Mutex sync.RWMutex
}

type MessageType byte

func (mt MessageType) String() string {
	return fmt.Sprintf("%d", mt)
}

func (mt MessageType) ToBytes() []byte {
	return []byte{(byte)(mt)}
}

type leaseTime uint32

func (lT leaseTime) String() string {
	return fmt.Sprintf("%d", lT)
}

func (lT leaseTime) ToBytes() []byte {
	time := (uint32)(lT)
	return []byte{(byte)(time >> 24), (byte)((time & 0x00FF0000) >> 16), (byte)((time & 0x0000FF00) >> 8), (byte)(time & 0x000000FF)}
}

type dhcpIP []byte

func (dIP dhcpIP) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", dIP[0], dIP[1], dIP[2], dIP[3])
}

func (dIP dhcpIP) ToBytes() []byte {
	return []byte(dIP)
}

var ServerIP dhcpIP

func CreateDHCPServer(amfConn *sctp.SCTPConn, mutex *sync.Mutex) (net.PacketConn, error) {

	AMFConn = amfConn
	ngapMutex = mutex

	return net.ListenPacket("udp", ":67")
}

var AMFConn *sctp.SCTPConn

func RunDHCPServer(udpServer net.PacketConn, ethSocketConn tglib.EthSocketConn, clients *Clients, conf Conf, ctx context.Context, wg *sync.WaitGroup) {

	defer wg.Done()

	addrs, err := ethSocketConn.Iface.Addrs()
	if err != nil {
		fmt.Println(err)
		return // TODO: fix possible errors in exception handling
	}

	for _, addr := range addrs {
		if ServerIP = (dhcpIP)(addr.(*net.IPNet).IP.To4()); ServerIP != nil {
			break
		}
	}
	if ServerIP == nil {
		fmt.Printf("Error recovering DHCP server IP address\n")
	}

	for {

		select {
		case <-ctx.Done():
			return
		default:
		}

		buf := make([]byte, 1024)

		udpPayloadSize, _, err := udpServer.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				continue
			}
			fmt.Printf("Error reading DHCP message: %s\n", err)
			continue
		} else if udpPayloadSize == 0 {
			continue
		}

		go response(ethSocketConn, buf, clients, conf)
	}

}

func response(ethSocketConn tglib.EthSocketConn, buf []byte, clients *Clients, conf Conf) {

	dhcp_msg, err := dhcpv4.FromBytes(buf) // dhcp message
	if err != nil {
		log.Print(err)
		return
	}

	switch messageType := dhcp_msg.Options[dhcpv4.OptionDHCPMessageType.Code()][0]; messageType {
	case dhcpv4.MessageTypeDiscover.ToBytes()[0]: // dhcp offer

		if shutdownStarted.Load() {
			nakIfShutdownStarted(dhcp_msg, ethSocketConn)
			return
		}

		offer, err := newOfferFromDiscover(dhcp_msg, clients, conf)
		if err != nil {
			log.Print(err)
			return
		}
		sendEthFromDHCP(offer, ethSocketConn)

	case dhcpv4.MessageTypeRequest.ToBytes()[0]: // dhcp request

		if shutdownStarted.Load() {
			nakIfShutdownStarted(dhcp_msg, ethSocketConn)
			return
		}

		ack, err := newAckFromRequest(dhcp_msg, clients)
		if err != nil {
			log.Print(err)
			return
		}
		sendEthFromDHCP(ack, ethSocketConn)

	case dhcpv4.MessageTypeRelease.ToBytes()[0]: // dhcp release
		releaseDHCP(dhcp_msg, clients, conf)

	default:
		return
	}

}

func newOfferFromDiscover(discover *dhcpv4.DHCPv4, clients *Clients, conf Conf) (*dhcpv4.DHCPv4, error) {

	macAddr := ([6]byte)(discover.ClientHWAddr)

	clients.Mutex.RLock()
	client, ok := clients.Value[macAddr]
	clients.Mutex.RUnlock()

	// Discover is ignored if there is an ongoing request
	if ok && (client.State == CodeRecvDiscover || client.State == CodeRecvRequest ||
		client.State == CodeRecvRelease) {
		return nil, fmt.Errorf("Ongoing request")
	}

	if !ok {
		client = ClientInfo{
			IP:                 nil,
			UE:                 nil,
			PDU:                nil,
			TEID:               0,
			UPFAddr:            nil,
			State:              CodeRecvDiscover,
			SessionEstablished: false,
		}
	} else {
		client.State = CodeRecvDiscover
	}

	// The state is set so that no other discover is processed
	clients.Mutex.Lock()
	clients.Value[macAddr] = client
	clients.Mutex.Unlock()

	// If !ok 						-> register, establish session and establish DHCP
	// If ok && !SessionEstablished -> establish session and establish DHCP
	// If ok && SessionEstablished	-> establish DHCP

	if !ok { // Register

		imsi, existsImsi := conf.Configuration.Clients[fmt.Sprintf("%X", macAddr)]

		// Return with error if MAC addr not registered in config file
		if !existsImsi {
			return nil, fmt.Errorf("Device not registered in config.yaml")
		}

		fmt.Println(">> Creating new UE with IMSI:", imsi)
		client.UE = CreateUE(
			imsi,
			conf.Configuration.K,
			conf.Configuration.OPC,
			conf.Configuration.OP,
		)

		fmt.Println(">> Registering UE with IMSI:", imsi)
		ngapMutex.Lock()
		client.UE, client.PDU, _ = RegisterUE(
			client.UE,
			conf.Configuration.Mnc,
			AMFConn,
		)
		ngapMutex.Unlock()

		time.Sleep(1 * time.Second)

	}

	if !ok || ok && !client.SessionEstablished { // Establish session

		fmt.Println(">> Establishing PDU session for", client.UE.Supi)
		ngapMutex.Lock()
		EstablishPDU(
			conf.Configuration.SST,
			conf.Configuration.SD,
			client.PDU,
			client.UE,
			AMFConn,
			conf.Configuration.Gnb_gtp,
			conf.Configuration.Upf_port,
			&client,
		)
		ngapMutex.Unlock()

		client.SessionEstablished = true

		time.Sleep(1 * time.Second)

	}

	// Establish DCHP

	offer, err := dhcpv4.New()
	if err != nil {
		return nil, err
	}

	offer.OpCode = dhcpv4.OpcodeBootReply
	offer.TransactionID = discover.TransactionID
	offer.ServerIPAddr = discover.ServerIPAddr
	offer.Flags = discover.Flags
	offer.GatewayIPAddr = discover.GatewayIPAddr
	offer.ClientHWAddr = discover.ClientHWAddr

	offer.YourIPAddr = client.IP

	offer.ServerHostName = "AGF\x00"

	offer.Options = dhcpv4.OptionsFromList(
		dhcpv4.Option{Code: dhcpv4.OptionDHCPMessageType, Value: dhcpv4.MessageTypeOffer},
		dhcpv4.Option{Code: dhcpv4.OptionServerIdentifier, Value: ServerIP},
		dhcpv4.Option{Code: dhcpv4.OptionIPAddressLeaseTime, Value: leaseTime(86400)}, // 1 day
		dhcpv4.Option{Code: dhcpv4.OptionSubnetMask, Value: dhcpIP([]byte{0xff, 0xff, 0xff, 0x00})},
	)

	client.State = CodeSentOffer

	clients.Mutex.Lock()
	clients.Value[macAddr] = client
	clients.Mutex.Unlock()

	return offer, nil

}

func newAckFromRequest(request *dhcpv4.DHCPv4, clients *Clients) (*dhcpv4.DHCPv4, error) {

	macAddr := ([6]byte)(request.ClientHWAddr)

	clients.Mutex.RLock()
	client, ok := clients.Value[macAddr]
	clients.Mutex.RUnlock()

	// Request is ignored if there is an ongoing request
	if ok && (client.State == CodeRecvDiscover || client.State == CodeRecvRequest ||
		client.State == CodeRecvRelease) {
		return nil, fmt.Errorf("Petición en curso")
	}

	// A NAK message is generated if there isn't an existing established session
	if !ok || (ok && !client.SessionEstablished) {
		return generateNAK(macAddr, request.TransactionID)
	}

	// The state is modified so that no other discover is processed
	client.State = CodeRecvRequest

	clients.Mutex.Lock()
	clients.Value[macAddr] = client
	clients.Mutex.Unlock()

	ack, err := dhcpv4.New()
	if err != nil {
		return nil, err
	}

	ack.OpCode = dhcpv4.OpcodeBootReply
	ack.TransactionID = request.TransactionID
	ack.ServerIPAddr = request.ServerIPAddr
	ack.Flags = request.Flags
	ack.GatewayIPAddr = request.GatewayIPAddr
	ack.ClientHWAddr = request.ClientHWAddr

	ack.YourIPAddr = client.IP

	ack.ServerHostName = "AGF\x00"

	ack.Options = dhcpv4.OptionsFromList(
		dhcpv4.Option{Code: dhcpv4.OptionDHCPMessageType, Value: dhcpv4.MessageTypeAck},
		dhcpv4.Option{Code: dhcpv4.OptionServerIdentifier, Value: ServerIP},
		dhcpv4.Option{Code: dhcpv4.OptionIPAddressLeaseTime, Value: leaseTime(86400)}, // 1 day
		dhcpv4.Option{Code: dhcpv4.OptionSubnetMask, Value: dhcpIP([]byte{0xff, 0xff, 0xff, 0x00})},
	)

	client.State = CodeSentAck

	clients.Mutex.Lock()
	clients.Value[macAddr] = client
	clients.Mutex.Unlock()

	return ack, nil

}

func generateNAK(mac [6]byte, xid dhcpv4.TransactionID) (*dhcpv4.DHCPv4, error) {

	nak, err := dhcpv4.New()
	if err != nil {
		return nil, err
	}

	nak.OpCode = dhcpv4.OpcodeBootReply
	nak.TransactionID = xid
	nak.ClientHWAddr = net.HardwareAddr(mac[:])

	nak.Options = dhcpv4.OptionsFromList(
		dhcpv4.Option{Code: dhcpv4.OptionDHCPMessageType, Value: dhcpv4.MessageTypeNak},
		dhcpv4.Option{Code: dhcpv4.OptionServerIdentifier, Value: ServerIP},
	)

	return nak, nil
}

func generateFORCERENEW(mac [6]byte) (*dhcpv4.DHCPv4, error) {

	frenew, err := dhcpv4.New()
	if err != nil {
		return nil, err
	}

	frenew.OpCode = dhcpv4.OpcodeBootReply
	frenew.ClientHWAddr = net.HardwareAddr(mac[:])

	frenew.Options = dhcpv4.OptionsFromList(
		dhcpv4.Option{Code: dhcpv4.OptionDHCPMessageType, Value: MessageType(0x09)},
		dhcpv4.Option{Code: dhcpv4.OptionServerIdentifier, Value: ServerIP},
	)

	return frenew, err

}

func ForceRenew(mac [6]byte, ethSocketConn tglib.EthSocketConn) error {
	forcerenew, err := generateFORCERENEW(mac)
	if err != nil {
		return err
	}

	sendEthFromDHCP(forcerenew, ethSocketConn)
	return nil
}

func releaseDHCP(release *dhcpv4.DHCPv4, clients *Clients, conf Conf) {

	macAddr := ([6]byte)(release.ClientHWAddr)

	clients.Mutex.RLock()
	client, ok := clients.Value[macAddr]
	clients.Mutex.RUnlock()

	// Request is ignored if there is an ongoing request
	if !ok || ok && (client.State == CodeRecvDiscover || client.State == CodeRecvRequest ||
		client.State == CodeRecvRelease) {
		return
	}

	client.State = CodeRecvRelease

	clients.Mutex.Lock()
	clients.Value[macAddr] = client
	clients.Mutex.Unlock()

	fmt.Println(">> Releasing PDU session for", client.UE.Supi)
	ngapMutex.Lock()
	ReleasePDU(
		conf.Configuration.SST,
		conf.Configuration.SD,
		client.UE,
		AMFConn,
	)
	time.Sleep(1 * time.Second)
	ngapMutex.Unlock()

	client.SessionEstablished = false
	client.State = CodeReleased

	clients.Mutex.Lock()
	clients.Value[macAddr] = client
	clients.Mutex.Unlock()

}

func nakIfShutdownStarted(dhcp_msg *dhcpv4.DHCPv4, ethSocketConn tglib.EthSocketConn) {

	nak, err := generateNAK(([6]byte)(dhcp_msg.ClientHWAddr), dhcp_msg.TransactionID)
	if err != nil {
		log.Print(err)
		return
	}
	sendEthFromDHCP(nak, ethSocketConn)

}

func sendEthFromDHCP(dhcp_msg *dhcpv4.DHCPv4, ethSocketConn tglib.EthSocketConn) {
	dhcp_msg_b := dhcp_msg.ToBytes()

	udp_hdr_b := make([]byte, 8+len(dhcp_msg_b))

	copy(udp_hdr_b[0:], []byte{0x00, 0x43, 0x00, 0x44})                                     // src and dst udp ports
	copy(udp_hdr_b[4:], []byte{uint8(len(udp_hdr_b) >> 8), uint8(len(udp_hdr_b) & 0x00ff)}) // udp + payload length
	copy(udp_hdr_b[6:], []byte{0x00, 0x00})                                                 // null checksum
	copy(udp_hdr_b[8:], dhcp_msg_b)                                                         // payload

	ip_hdr := ipv4.Header{
		Version:  4,
		Len:      20,
		TotalLen: 20 + len(udp_hdr_b),
		TTL:      64,
		Protocol: 17,
		Src:      dhcp_msg.Options[dhcpv4.OptionServerIdentifier.Code()],
		Dst:      dhcp_msg.YourIPAddr,
	}

	ip_hdr_b, err := ip_hdr.Marshal()
	if err != nil {
		log.Print(err)
		return
	}

	var checksum_value_32 uint32 = 0
	for i := 0; i < len(ip_hdr_b); i += 2 {
		checksum_value_32 += (uint32)(ip_hdr_b[i])<<8 + (uint32)(ip_hdr_b[i+1])
	}
	checksum_value_16 := ^(uint16)(checksum_value_32&0xFFFF + checksum_value_32>>16)
	checksum_b := []byte{(byte)(checksum_value_16 >> 8), (byte)(checksum_value_16 & 0xFF)}

	copy(ip_hdr_b[10:], checksum_b)

	ip_hdr_b = append(ip_hdr_b, udp_hdr_b...)

	eth_frame_b := make([]byte, len(ip_hdr_b)+14)

	copy(eth_frame_b[0:], dhcp_msg.ClientHWAddr)
	copy(eth_frame_b[6:], ethSocketConn.Iface.HardwareAddr)
	copy(eth_frame_b[12:], []byte{0x08, 0x00}) // Type: IPv4
	copy(eth_frame_b[14:], ip_hdr_b)

	err = syscall.Sendto(ethSocketConn.Fd, eth_frame_b, 0, &(ethSocketConn.Addr))
	if err != nil {
		log.Print(err)
		return
	}

}

func SetShutdownStarted() {
	shutdownStarted.Store(true)
}
