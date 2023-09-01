package main

// #cgo CFLAGS: -pthread
// #include <signal.h>
// #include <pthread.h>
import "C"

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"stgutg"
	"tglib"
)

func main() {

	// Needed to assert that no two NGAP exchanges happen at the same time
	var ngapMutex sync.Mutex

	var clients stgutg.Clients
	clients.Value = make(map[[6]byte]stgutg.ClientInfo)

	var c stgutg.Conf
	c.GetConfiguration()

	mode := stgutg.GetMode(os.Args)

	if mode == 1 {
		fmt.Println("TRAFFIC MODE")
		fmt.Println("----------------------")

		fmt.Println(">> Connecting to AMF")
		amfConn, err := tglib.ConnectToAmf(
			c.Configuration.Amf_ngap,
			c.Configuration.Gnb_ngap,
			c.Configuration.Amf_port,
			c.Configuration.Gnbn_port,
		)
		stgutg.ManageError("Error in connection to AMF", err)

		fmt.Println(">> Managing NG Setup")
		stgutg.ManageNGSetup(
			amfConn,
			c.Configuration.Gnb_id,
			c.Configuration.Gnb_bitlength,
			c.Configuration.Gnb_name,
		)

		fmt.Println(">> Connecting to UPF")
		upfFD, err := tglib.ConnectToUpf(c.Configuration.Gnbg_port)
		stgutg.ManageError("Error in connection to UPF", err)

		fmt.Println(">> Opening traffic interfaces")
		ethSocketConn, err := tglib.NewEthSocketConn(c.Configuration.SrcIface)
		stgutg.ManageError("Error creating Ethernet socket", err)

		ipSocketConn, err := tglib.NewIPSocketConn()
		stgutg.ManageError("Error creating IP socket", err)

		fmt.Println(">> Creating DHCP Server")
		udpServer, err := stgutg.CreateDHCPServer(amfConn, &ngapMutex)
		stgutg.ManageError("Error in creating UDP Server", err)
		var clients stgutg.Clients
		clients.Value = make(map[[6]byte]stgutg.ClientInfo)

		var stopProgram = make(chan os.Signal)
		signal.Notify(stopProgram, syscall.SIGTERM)
		signal.Notify(stopProgram, syscall.SIGINT)

		ctx, cancelFunc := context.WithCancel(context.Background())
		dhcpCtx, dhcpCancelFunc := context.WithCancel(context.Background())
		wg := &sync.WaitGroup{}
		utg_ul_thread_chan := make(chan stgutg.Thread)

		wg.Add(3)

		fmt.Println(">> Starting DHCP Server")
		go stgutg.RunDHCPServer(udpServer, ethSocketConn, &clients, c, dhcpCtx, wg)

		fmt.Println(">> Listening to traffic responses")
		go stgutg.ListenForResponses(ipSocketConn, upfFD, ctx, wg)

		fmt.Println(">> Waiting for traffic to send (Press Ctrl+C to quit)")
		go stgutg.SendTraffic(upfFD, ethSocketConn, &clients, ctx, wg, utg_ul_thread_chan)

		utg_ul_thread := <-utg_ul_thread_chan

		// Program interrupted
		sig := <-stopProgram
		fmt.Println("\n>> Exiting program:", sig, "found")

		cancelFunc() // Call for UTG to shut down

		// Stop packet capture for both interfaces of UTG
		C.pthread_kill(C.ulong(utg_ul_thread.Id), C.SIGUSR1)
		syscall.Shutdown(upfFD, syscall.SHUT_RD)

		// Deny all new incoming DHCP requests
		stgutg.SetShutdownStarted()

		clients.Mutex.Lock()
		for clientMAC, client := range clients.Value {

			if client.SessionEstablished {
				fmt.Println(">> Releasing PDU session for", client.UE.Supi)
				ngapMutex.Lock()
				stgutg.ReleasePDU(
					c.Configuration.SST,
					c.Configuration.SD,
					client.UE,
					amfConn,
				)
				ngapMutex.Unlock()
				time.Sleep(1 * time.Second)

				stgutg.ForceRenew(clientMAC, ethSocketConn)
			}

			fmt.Println(">> Deregistering UE", client.UE.Supi)
			ngapMutex.Lock()
			stgutg.DeregisterUE(
				client.UE,
				c.Configuration.Mnc,
				amfConn,
			)
			ngapMutex.Unlock()
			time.Sleep(2 * time.Second)

			delete(clients.Value, clientMAC)
		}
		clients.Mutex.Unlock()

		time.Sleep(1 * time.Second)

		// Call for DHCP Server to shut down
		dhcpCancelFunc()
		udpServer.Close()

		amfConn.Close()

		fmt.Println(">> Waiting for UTG and DHCP Server to shut down")
		wg.Wait() // Wait for UTG and DHCP Server to shut down, then close interfaces

		fmt.Println(">> Closing network interfaces")
		syscall.Close(upfFD)
		syscall.Close(ethSocketConn.Fd)
		syscall.Close(ipSocketConn.Fd)

		time.Sleep(1 * time.Second)
		os.Exit(0)

	} else if mode == 2 {
		fmt.Println("TEST MODE")
		fmt.Println("----------------------")

		// TODO: Test Mode

	}
}
