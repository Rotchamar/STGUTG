package stgutg

// UTG
// Functions that manage the User Traffic Generation capabilites. It includes
// capturing traffic from clients connected to the connector and injecting the
// traffic in the GTP tunnel.
// It also provides a function to capture and forward the traffic sent to the
// client.
// Version: 0.9
// Date: 9/6/21

import (
	"tglib"

	"bytes"
	"fmt"
	"net"
	"syscall"
)

// ListenForResponses
// Function that keeps listening in the network interface connected to the UPF (dst)
// and captures the traffic to the client app. It decapsulates the packet from the GTP
// tunnel, then checks the destination IP and looks up the corresponding MAC address
// in the system ARP table. It then builds the Eth header and sends the packet back to
// the client.
func ListenForResponses(ethSocketConn tglib.EthSocketConn, upfConn *net.UDPConn) {

	fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)

	rcvBuf := make([]byte, 1500)

	for {

		udpPayloadSize, err := upfConn.Read(rcvBuf)

		ManageError("Error capturing receiving traffic", err)

		enc_b := rcvBuf[:udpPayloadSize]

		gtp_hdr_size := 8
		if enc_b[0]&4 != 0 {
			gtp_hdr_size += 4 + int(enc_b[12])*4
		} else if enc_b[0]&3 != 0 {
			gtp_hdr_size += 4
		}
		ipPkt := enc_b[gtp_hdr_size:]
		ManageError("Error capturing receiving traffic", err)

		var ipAddr [4]byte
		copy(ipAddr[:], ipPkt[16:])

		addr := syscall.SockaddrInet4{
			Addr: ipAddr,
		}

		// fmt.Println(ipAddr)

		err = syscall.Sendto(fd, ipPkt, 0, &addr)
		ManageError("Sendto", err)

	}
}

// SendTraffic
// Function that captures traffic in the interface connected to the client or clients that
// generate the user traffic (src), emulating the UEs.
// It checks the source IP address to determine the TEID to use when adding the GTP
// header and then sends the traffic to the UPF.
func SendTraffic(upfConn *net.UDPConn, ethSocketConn tglib.EthSocketConn, teids []Ipteid) {

	data := make([]byte, 1500)

	for {
		frameSize, _, err := syscall.Recvfrom(ethSocketConn.Fd, data, 0)
		if err != nil {
			fmt.Printf("Error receiving traffic: %s", err)
			continue
		}

		if bytes.Equal(data[0:6], []byte(ethSocketConn.Iface.HardwareAddr)) &&
			bytes.Equal(data[12:14], []byte{0x88, 0x64}) &&
			bytes.Equal(data[20:22], []byte{0x00, 0x21}) {

			ipPkt := data[22:frameSize]

			src_ip := ipPkt[12:16]

			//fmt.Println(src_ip)
			teid := GetTEID(src_ip, teids)

			gtpHdr, err := tglib.BuildGTPv1Header(false, 0, false, 0, false, 0, uint16(len(ipPkt)), teid)
			ManageError("Error capturing and sending traffic", err)

			_, err = upfConn.Write(append(gtpHdr, ipPkt...))
			ManageError("Error capturing and sending traffic", err)

		}
	}
}
