package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {

	var (
		device string = "\\Device\\NPF_{02A4BA67-8CF3-4503-AC97-6C2F3F46FF13}"
		//"\\Device\\NPF_{A8169A23-F588-4FEB-8008-ED010D5C65B5}"
		snapshot_len int32 = 1024
		promiscuous  bool  = false
		err          error
		timeout      time.Duration = 30 * time.Second
		handle       *pcap.Handle
	)

	// Use the handle as a packet source to process all packets
	index := 0
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var icmpv6e layers.ICMPv6Echo
	var icmpv4 layers.ICMPv4
	var icmpv6 layers.ICMPv6
	var icmpv6ad layers.ICMPv6RouterAdvertisement
	var icmpv6r layers.ICMPv6Redirect
	var udp layers.UDP
	var arp layers.ARP
	var igmp layers.IGMP
	var igmpv1or2 layers.IGMPv1or2

	// var igmpv3GR layers.IGMPv3GroupRecord

	var payload gopacket.Payload
	dlc := gopacket.DecodingLayerContainer(gopacket.DecodingLayerArray(nil))
	dlc = dlc.Put(&eth)
	dlc = dlc.Put(&ip4)
	dlc = dlc.Put(&ip6)
	dlc = dlc.Put(&tcp)
	dlc = dlc.Put(&udp)
	dlc = dlc.Put(&icmpv4)
	dlc = dlc.Put(&icmpv6)
	dlc = dlc.Put(&igmp)
	dlc = dlc.Put(&arp)
	dlc = dlc.Put(&payload)
	dlc = dlc.Put(&igmpv1or2)
	dlc = dlc.Put(&icmpv6e)

	dlc = dlc.Put(&icmpv6ad)
	dlc = dlc.Put(&icmpv6r)
	// decoder, _ := dlc.Decoder(layers.LayerTypeUDP)
	decoder := dlc.LayersDecoder(layers.LayerTypeEthernet, gopacket.NilDecodeFeedback)
	decoded := make([]gopacket.LayerType, 0, 20)

	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	// BPFInst, err := handle.CompileBPFFilter("udp")
	// if err != nil {
	// 	fmt.Println("compile error :", err)
	// 	// panic(err)
	// }
	// err = handle.SetBPFInstructionFilter(BPFInst)
	// if err != nil {
	// 	fmt.Println("compile error :", err)
	// 	// panic(err)
	// }
	if err := handle.SetBPFFilter("tcp"); err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		index++

		it, _ := decoder(packet.Data(), &decoded)
		// if err != nil {
		// 	continue
		// }
		if it != gopacket.LayerTypeZero {
			fmt.Fprintf(os.Stderr, "unknown layer type: %v\n", it)
			continue

		}
		fmt.Println("Decoded :", decoded)
		for _, typ := range decoded {

			switch typ {
			// case layers.LayerTypeEthernet:
			// 	fmt.Println("    Eth ", eth.SrcMAC, eth.DstMAC)
			// case layers.LayerTypeIPv4:
			// 	fmt.Println("    IP4 ", ip4.SrcIP, ip4.DstIP)
			// case layers.LayerTypeIPv6:
			// 	fmt.Println("    IP6 ", ip6.SrcIP, ip6.DstIP)
			case layers.LayerTypeTCP:
				fmt.Println("    TCP ", tcp.SrcPort, tcp.DstPort)
				fmt.Println(tcp.LayerContents())
				fmt.Println(tcp.Payload)
				fmt.Println(tcp.LayerPayload())
			case layers.LayerTypeUDP:
				fmt.Println("    UDP ", udp.SrcPort, udp.DstPort)
				fmt.Println(udp.Payload)
				fmt.Println(udp.LayerPayload())
				// case layers.LayerTypeARP:
				// 	fmt.Println("    ARP ", arp.SourceHwAddress, arp.DstHwAddress)
				// case layers.LayerTypeICMPv4:
				// 	fmt.Println("    ICMPv4 ", icmpv4.Id, icmpv4.Seq)
				// 	fmt.Println("Decoded :", decoded)

				// case layers.LayerTypeICMPv6:
				// 	fmt.Println("    ICMPv6 ", icmpv6.TypeCode)
				// 	fmt.Println("Decoded :", decoded)

				// case layers.LayerTypeICMPv6Echo:
				// 	fmt.Println("    ICMPv6e ", icmpv6e.SeqNumber)
				// 	fmt.Println("Decoded :", decoded)
				// case layers.LayerTypeICMPv6NeighborAdvertisement:
				// 	fmt.Println("    ICMPv6ead ", icmpv6ad.ReachableTime)
				// 	fmt.Println("Decoded :", decoded)

				// case layers.LayerTypeIGMP:
				// 	fmt.Println("    IGMP ", igmp.Type.String())
				// 	fmt.Println("    IGMP ", igmp.Version)
			}
		}
		if index == 500 {
			handle.Close()
			return

		}
	}
}
