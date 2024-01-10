package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
)

var iface string

func main() {
	var rootCmd = &cobra.Command{Use: "packet_counter"}

	rootCmd.Flags().StringVarP(&iface, "interface", "i", "ens3", "Network interface name")
	rootCmd.AddCommand(startCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start counting packets per second per IP on the specified network interface",
	Run: func(cmd *cobra.Command, args []string) {
		handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		ticker := time.NewTicker(time.Second)

		signalChan := make(chan os.Signal, 1)
		signal.Notify(signalChan, os.Interrupt)

		for {
			select {
			case <-ticker.C:
				printStats()
				resetStats()

			case <-signalChan:
				ticker.Stop()
				fmt.Println("\nInterrupt received. Exiting...")
				os.Exit(0)

			case packet := <-packetSource.Packets():
				updateStats(packet)
			}
		}
	},
}

var packetCount = make(map[string]int)

func printStats() {
	fmt.Println("Packets per second per IP:")
	for ip, count := range packetCount {
		fmt.Printf("%s: %d\n", ip, count)
	}
	fmt.Println("---------------------------")
}

func resetStats() {
	packetCount = make(map[string]int)
}

func updateStats(packet gopacket.Packet) {
	networkLayer := packet.NetworkLayer()
	if networkLayer != nil && networkLayer.LayerType() == layers.LayerTypeIPv4 {
		ip, _ := networkLayer.(*layers.IPv4)
		srcIP := ip.SrcIP.String()
		packetCount[srcIP]++
	}
}
