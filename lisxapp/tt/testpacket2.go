package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type treeItem map[string][]string
type treeItemByte map[string][]byte
type TreeDataStruct struct {
	PacketIndex int
	TreeIten    treeItem
	Data        treeItemByte
}

func main() {
	TreeData := TreeDataStruct{

		PacketIndex: 0,
		TreeIten:    make(treeItem),
		Data:        make(treeItemByte),
	}
	var (
		device       string = "\\Device\\NPF_{A8169A23-F588-4FEB-8008-ED010D5C65B5}"
		snapshot_len int32  = 1024
		promiscuous  bool   = false
		err          error
		timeout      time.Duration = 30 * time.Second
		handle       *pcap.Handle

		eth layers.Ethernet
		ip4 layers.IPv4
		ip6 layers.IPv6
		tcp layers.TCP
		udp layers.UDP
		arp layers.ARP
		// icmpv6na layers.ICMPv6NeighborAdvertisement
		// icmpv6ns layers.ICMPv6NeighborSolicitation
		icmpv4 layers.ICMPv4
		icmpv6 layers.ICMPv6

		igmp      layers.IGMP
		igmpv1or2 layers.IGMPv1or2
		// igmpv3    layers.IGMPv3GroupRecordType
		payload gopacket.Payload
	)
	index := 0
	// 打开某一网络设备
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	// Use the handle as a packet source to process all packets

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
	// dlc = dlc.Put(&igmpv3)

	// 使用map类型是不是能级析出一个packet中包含哪些协议
	decoder := dlc.LayersDecoder(layers.LayerTypeEthernet, gopacket.NilDecodeFeedback)
	decoded := make([]gopacket.LayerType, 0, 20)
	// parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp)
	// decoded := []gopacket.LayerType{}
	// parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4,
	// 	&ip6, &tcp, &udp, &icmpv4, &icmpv6, &igmp, &arp, &payload)
	// decodedLayers := make([]gopacket.LayerType, 0, 10)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		index++

		// Process packet here
		// packet.D ata()
		// if err := parser.DecodeLayers([]byte(packet.Data()), &decoded); err != nil {
		// 	fmt.Fprintf(os.Stderr, "Could not decode layers: %v\n", err)
		// 	continue
		// }
		// fmt.Println("      ppacket.Metadata().CaptureInfo %v\n", packet.Metadata().AncillaryData)
		it, err := decoder(packet.Data(), &decoded)

		if it != gopacket.LayerTypeZero {
			fmt.Fprintf(os.Stderr, "unknown layer type: %v\n", it)
			continue

		}
		fmt.Println("Decoded :", decoded)

		/*
		   packet.Layer() 返回指定层的数据
		*/

		// fmt.Println("packrt layer", packet.Layer(layers.LayerTypeUDP))
		var LayerTypeString []string

		for _, typ := range decoded {

			// fmt.Println("  Successfully decoded layer type", typ)
			switch typ {

			case layers.LayerTypeEthernet:
				LayerTypeString = append(LayerTypeString, "ETH")
				// TreeData.TreeIten := treeItem{}
				TreeData.TreeIten["ETH"] = append(TreeData.TreeIten["ETH"], "Source")
				TreeData.TreeIten["ETH"] = append(TreeData.TreeIten["ETH"], "Destination")
				// subItem := treeItem{}
				TreeData.TreeIten["Source"] = append(TreeData.TreeIten["Source"], eth.SrcMAC.String())
				TreeData.TreeIten["Destination"] = append(TreeData.TreeIten["Destination"], eth.DstMAC.String())
				// TreeData.TreeIten = append(TreeData.TreeIten, TreeData.TreeIten)
				// TreeData.TreeIten = append(TreeData.TreeIten, subItem)
				// fmt.Println("    Eth ", eth.SrcMAC.String(), eth.DstMAC.String())
			case layers.LayerTypeIPv4:
				LayerTypeString = append(LayerTypeString, "IPv4")
				// rootItem := treeItem{}
				TreeData.TreeIten["IPv4"] = append(TreeData.TreeIten["IPv4"], "Version: "+strconv.Itoa(int(ip4.Version)))
				TreeData.TreeIten["IPv4"] = append(TreeData.TreeIten["IPv4"], "HeaderLength: "+strconv.Itoa(int(ip4.Length))+" bytes")
				// TreeData.TreeIten["IPv4"] = append(TreeData.TreeIten["IPv4"], "TotalLength")
				TreeData.TreeIten["IPv4"] = append(TreeData.TreeIten["IPv4"], "FLAGS")
				TreeData.TreeIten["IPv4"] = append(TreeData.TreeIten["IPv4"], "Source: "+ip4.SrcIP.String())
				TreeData.TreeIten["IPv4"] = append(TreeData.TreeIten["IPv4"], "Destination: "+ip4.DstIP.String())
				TreeData.TreeIten["IPv4"] = append(TreeData.TreeIten["IPv4"], "TimeToLive: "+strconv.Itoa(int(ip4.TTL)))

				TreeData.TreeIten["FLAGS"] = append(TreeData.TreeIten["FLAGS"], ip4.Flags.String())

				fmt.Println("    IP4 ", ip4.SrcIP, ip4.DstIP)

			case layers.LayerTypeIPv6:

				LayerTypeString = append(LayerTypeString, "IPv6")

				TreeData.TreeIten["IPv6"] = append(TreeData.TreeIten["IPv6"], "Version: "+strconv.Itoa(int(ip6.Version)))
				TreeData.TreeIten["IPv6"] = append(TreeData.TreeIten["IPv6"], "HeaderLength: "+strconv.Itoa(int(ip6.Length))+" bytes")
				// TreeData.TreeIten["IPv4"] = append(TreeData.TreeIten["IPv4"], "TotalLength")
				TreeData.TreeIten["IPv6"] = append(TreeData.TreeIten["IPv6"], "FLAGS")
				TreeData.TreeIten["IPv6"] = append(TreeData.TreeIten["IPv6"], "Source: "+ip6.SrcIP.String())
				TreeData.TreeIten["IPv6"] = append(TreeData.TreeIten["IPv6"], "Destination: "+ip6.DstIP.String())
				TreeData.TreeIten["IPv6"] = append(TreeData.TreeIten["IPv6"], "NextLayer Type "+ip6.NextHeader.String())

				// TreeData.TreeIten = append(TreeData.TreeIten, TreeData.TreeIten)
				// // TreeData.TreeIten = append(TreeData.TreeIten, subItem)
				fmt.Println("    IP6 ", ip6.SrcIP, ip6.DstIP)
			case layers.LayerTypeTCP:

				LayerTypeString = append(LayerTypeString, "TCP")

				TreeData.TreeIten["TCP"] = append(TreeData.TreeIten["TCP"], "SourcePort: "+tcp.SrcPort.String())
				TreeData.TreeIten["TCP"] = append(TreeData.TreeIten["TCP"], "DestinationPort: "+tcp.DstPort.String())
				TreeData.TreeIten["TCP"] = append(TreeData.TreeIten["TCP"], "FLAGS")
				TreeData.TreeIten["TCP"] = append(TreeData.TreeIten["TCP"], "Window: "+strconv.Itoa(int(tcp.Window)))
				TreeData.TreeIten["TCP"] = append(TreeData.TreeIten["TCP"], "UrgentPointer: "+strconv.Itoa(int(tcp.Urgent)))

				TreeData.TreeIten["FLAGS"] = append(TreeData.TreeIten["FLAGS"], "FIN: "+strconv.FormatBool(tcp.FIN))
				TreeData.TreeIten["FLAGS"] = append(TreeData.TreeIten["FLAGS"], "SYN: "+strconv.FormatBool(tcp.SYN))
				TreeData.TreeIten["FLAGS"] = append(TreeData.TreeIten["FLAGS"], "RST: "+strconv.FormatBool(tcp.RST))
				TreeData.TreeIten["FLAGS"] = append(TreeData.TreeIten["FLAGS"], "PSH: "+strconv.FormatBool(tcp.PSH))
				TreeData.TreeIten["FLAGS"] = append(TreeData.TreeIten["FLAGS"], "ACK: "+strconv.FormatBool(tcp.ACK))
				TreeData.TreeIten["FLAGS"] = append(TreeData.TreeIten["FLAGS"], "URG: "+strconv.FormatBool(tcp.URG))
				TreeData.TreeIten["FLAGS"] = append(TreeData.TreeIten["FLAGS"], "ECE: "+strconv.FormatBool(tcp.ECE))
				TreeData.TreeIten["FLAGS"] = append(TreeData.TreeIten["FLAGS"], "CWR: "+strconv.FormatBool(tcp.CWR))
				TreeData.TreeIten["FLAGS"] = append(TreeData.TreeIten["FLAGS"], "ACK: "+strconv.FormatBool(tcp.ACK))
				TreeData.TreeIten["FLAGS"] = append(TreeData.TreeIten["FLAGS"], "NS: "+strconv.FormatBool(tcp.NS))
				// TreeData.TreeIten = append(TreeData.TreeIten, TreeData.TreeIten)
				// TreeData.TreeIten = append(TreeData.TreeIten, subItem)

				fmt.Println("    TCP ", tcp.SrcPort, tcp.DstPort)
			case layers.LayerTypeUDP:
				LayerTypeString = append(LayerTypeString, "UDP")

				TreeData.TreeIten["UDP"] = append(TreeData.TreeIten["UDP"], "SourcePort: "+udp.SrcPort.String())
				TreeData.TreeIten["UDP"] = append(TreeData.TreeIten["UDP"], "DestinationPort: "+udp.DstPort.String())
				TreeData.TreeIten["UDP"] = append(TreeData.TreeIten["UDP"], "Length: "+strconv.Itoa(int(udp.Length))+" bytes")
				// TreeData.TreeIten["UDP"] = append(TreeData.TreeIten["UDP"], "Payload: "+string(udp.Payload))
				// TreeData.TreeIten = append(TreeData.TreeIten, TreeData.TreeIten)
				// TreeData.TreeIten = append(TreeData.TreeIten, subItem)
				fmt.Println("    UDP ", udp.SrcPort, udp.DstPort)
			case layers.LayerTypeARP:
				LayerTypeString = append(LayerTypeString, "ARP")

				TreeData.TreeIten["ARP"] = append(TreeData.TreeIten["ARP"], "ProtocolType: "+strconv.Itoa(int(arp.Protocol)))
				TreeData.TreeIten["ARP"] = append(TreeData.TreeIten["ARP"], "HardwareSize: "+strconv.Itoa(int(arp.HwAddressSize)))
				TreeData.TreeIten["ARP"] = append(TreeData.TreeIten["ARP"], "OpCode: "+strconv.Itoa(int(arp.Operation)))
				ipSender := fmt.Sprintf("%d.%d.%d.%d", arp.SourceProtAddress[0], arp.SourceProtAddress[1],
					arp.SourceProtAddress[2], arp.SourceProtAddress[3])
				ipTarget := fmt.Sprintf("%d.%d.%d.%d", arp.DstProtAddress[0], arp.DstProtAddress[1],
					arp.DstProtAddress[2], arp.DstProtAddress[3])
				TreeData.TreeIten["ARP"] = append(TreeData.TreeIten["ARP"], "Sender MAC Address: "+string(arp.SourceHwAddress))
				TreeData.TreeIten["ARP"] = append(TreeData.TreeIten["ARP"], "Sender IP Address: "+string(arp.SourceProtAddress))
				TreeData.TreeIten["ARP"] = append(TreeData.TreeIten["ARP"], "Target MAC Address: "+ipTarget)
				TreeData.TreeIten["ARP"] = append(TreeData.TreeIten["ARP"], "Target IP Address: "+ipSender)
				// TreeData.TreeIten = append(TreeData.TreeIten, TreeData.TreeIten)
				// TreeData.TreeIten = append(TreeData.TreeIten, subItem)

				fmt.Println("   ARP ", arp.SourceHwAddress, arp.DstHwAddress)
				// ipp := net.ParseIP(string(arp.SourceProtAddress[:]))

			case layers.LayerTypeIGMP:
				LayerTypeString = append(LayerTypeString, "IGMP")

				TreeData.TreeIten["IGMP"] = append(TreeData.TreeIten["IGMP"], "Type: "+igmp.Type.String())
				TreeData.TreeIten["IGMP"] = append(TreeData.TreeIten["IGMP"], "Version: "+strconv.Itoa(int(igmp.Version)))
				TreeData.TreeIten["IGMP"] = append(TreeData.TreeIten["IGMP"], "Max Resp Time: "+igmp.MaxResponseTime.String())
				TreeData.TreeIten["IGMP"] = append(TreeData.TreeIten["IGMP"], "Checksum: "+strconv.Itoa(int(igmp.Checksum)))
				TreeData.TreeIten["IGMP"] = append(TreeData.TreeIten["IGMP"], "Multicast Address: "+igmp.GroupAddress.String())
				// TreeData.TreeIten = append(TreeData.TreeIten, TreeData.TreeIten)
				// TreeData.TreeIten = append(TreeData.TreeIten, subItem)
				// fmt.Println("   IGMP ", igmp.GroupAddress)

			case layers.LayerTypeICMPv4:
				LayerTypeString = append(LayerTypeString, "ICMPv4")

				fmt.Println("    ICMPv4 ", icmpv4.Id, icmpv4.Seq)
			case layers.LayerTypeICMPv6:

				LayerTypeString = append(LayerTypeString, "ICMPv6")

				TreeData.TreeIten["ICMPv6"] = append(TreeData.TreeIten["ICMPv6"], "Type: "+icmpv6.TypeCode.String())
				TreeData.TreeIten["ICMPv6"] = append(TreeData.TreeIten["ICMPv6"], "Code: "+strconv.Itoa(int(icmpv6.TypeCode)))
				// TreeData.TreeIten["ICMPv6"] = append(TreeData.TreeIten["ICMPv6"], "Multicast Address Recode Changed to execlude: "+icmpv6.)
				// TreeData.TreeIten = append(TreeData.TreeIten, TreeData.TreeIten)
				// TreeData.TreeIten = append(TreeData.TreeIten, subItem)
				fmt.Println("    ICMPv6 ", icmpv6.TypeCode)

			case gopacket.LayerTypePayload:
				// TreeData.TreeIten := treeItem{}
				LayerTypeString = append(LayerTypeString, "PAYLOAD")
				// TreeData.TreeIten["PAYLOAD"] = append(TreeData.TreeIten["PAYLOAD"])
				subItemBinary := treeItemByte{}

				subItemBinary["PAYLOAD"] = payload.Payload()
				// TreeData.TreeIten = append(TreeData.TreeIten, TreeData.TreeIten)
				TreeData.Data = subItemBinary

			}
		}
		TreeData.PacketIndex = index
		TreeRoot := treeItem{}
		TreeRoot[""] = LayerTypeString
		// TreeData.TreeIten = append(TreeData.TreeIten, TreeRoot)
		if index == 100 {
			handle.Close()
			return
		}
		fmt.Printf("packet index :%d, tree Struct: %v,  data: %X\n", TreeData.PacketIndex, TreeData.TreeIten, TreeData.Data)

		if err != nil {
			fmt.Println("  Error encountered:", err)

		}
	}
}

// switch typ {

// case layers.LayerTypeEthernet:
// 	LayerTypeString = append(LayerTypeString, "ETH")
// 	rootItem := treeItem{}
// 	rootItem["ETH"] = append(rootItem["ETH"], "Source")
// 	rootItem["ETH"] = append(rootItem["ETH"], "Destination")
// 	subItem := treeItem{}
// 	subItem["Source"] = append(subItem["Source"], eth.SrcMAC.String())
// 	subItem["Destination"] = append(subItem["Destination"], eth.DstMAC.String())
// 	TreeData.TreeIten = append(TreeData.TreeIten, rootItem)
// 	TreeData.TreeIten = append(TreeData.TreeIten, subItem)
// 	// fmt.Println("    Eth ", eth.SrcMAC.String(), eth.DstMAC.String())
// case layers.LayerTypeIPv4:
// 	LayerTypeString = append(LayerTypeString, "IPv4")
// 	rootItem := treeItem{}
// 	rootItem["IPv4"] = append(rootItem["IPv4"], "Version: "+strconv.Itoa(int(ip4.Version)))
// 	rootItem["IPv4"] = append(rootItem["IPv4"], "HeaderLength: "+strconv.Itoa(int(ip4.Length))+" bytes")
// 	// rootItem["IPv4"] = append(rootItem["IPv4"], "TotalLength")
// 	rootItem["IPv4"] = append(rootItem["IPv4"], "FLAGS")
// 	rootItem["IPv4"] = append(rootItem["IPv4"], "Source: "+ip4.SrcIP.String())
// 	rootItem["IPv4"] = append(rootItem["IPv4"], "Destination: "+ip4.DstIP.String())
// 	rootItem["IPv4"] = append(rootItem["IPv4"], "TimeToLive: "+strconv.Itoa(int(ip4.TTL)))
// 	subItem := treeItem{}
// 	subItem["FLAGS"] = append(subItem["FLAGS"], ip4.Flags.String())

// 	TreeData.TreeIten = append(TreeData.TreeIten, rootItem)
// 	TreeData.TreeIten = append(TreeData.TreeIten, subItem)
// 	fmt.Println("    IP4 ", ip4.SrcIP, ip4.DstIP)

// case layers.LayerTypeIPv6:

// 	LayerTypeString = append(LayerTypeString, "IPv6")
// 	rootItem := treeItem{}
// 	rootItem["IPv6"] = append(rootItem["IPv6"], "Version: "+strconv.Itoa(int(ip6.Version)))
// 	rootItem["IPv6"] = append(rootItem["IPv6"], "HeaderLength: "+strconv.Itoa(int(ip6.Length))+" bytes")
// 	// rootItem["IPv4"] = append(rootItem["IPv4"], "TotalLength")
// 	rootItem["IPv6"] = append(rootItem["IPv6"], "FLAGS")
// 	rootItem["IPv6"] = append(rootItem["IPv6"], "Source: "+ip6.SrcIP.String())
// 	rootItem["IPv6"] = append(rootItem["IPv6"], "Destination: "+ip6.DstIP.String())
// 	rootItem["IPv6"] = append(rootItem["IPv6"], "NextLayer Type "+ip6.NextHeader.String())

// 	TreeData.TreeIten = append(TreeData.TreeIten, rootItem)
// 	// TreeData.TreeIten = append(TreeData.TreeIten, subItem)
// 	fmt.Println("    IP6 ", ip6.SrcIP, ip6.DstIP)
// case layers.LayerTypeTCP:

// 	LayerTypeString = append(LayerTypeString, "TCP")
// 	rootItem := treeItem{}
// 	rootItem["TCP"] = append(rootItem["TCP"], "SourcePort: "+tcp.SrcPort.String())
// 	rootItem["TCP"] = append(rootItem["TCP"], "DestinationPort: "+tcp.DstPort.String())
// 	rootItem["TCP"] = append(rootItem["TCP"], "FLAGS")
// 	rootItem["TCP"] = append(rootItem["TCP"], "Window: "+strconv.Itoa(int(tcp.Window)))
// 	rootItem["TCP"] = append(rootItem["TCP"], "UrgentPointer: "+strconv.Itoa(int(tcp.Urgent)))

// 	subItem := treeItem{}
// 	subItem["FLAGS"] = append(subItem["FLAGS"], "FIN: "+strconv.FormatBool(tcp.FIN))
// 	subItem["FLAGS"] = append(subItem["FLAGS"], "SYN: "+strconv.FormatBool(tcp.SYN))
// 	subItem["FLAGS"] = append(subItem["FLAGS"], "RST: "+strconv.FormatBool(tcp.RST))
// 	subItem["FLAGS"] = append(subItem["FLAGS"], "PSH: "+strconv.FormatBool(tcp.PSH))
// 	subItem["FLAGS"] = append(subItem["FLAGS"], "ACK: "+strconv.FormatBool(tcp.ACK))
// 	subItem["FLAGS"] = append(subItem["FLAGS"], "URG: "+strconv.FormatBool(tcp.URG))
// 	subItem["FLAGS"] = append(subItem["FLAGS"], "ECE: "+strconv.FormatBool(tcp.ECE))
// 	subItem["FLAGS"] = append(subItem["FLAGS"], "CWR: "+strconv.FormatBool(tcp.CWR))
// 	subItem["FLAGS"] = append(subItem["FLAGS"], "ACK: "+strconv.FormatBool(tcp.ACK))
// 	subItem["FLAGS"] = append(subItem["FLAGS"], "NS: "+strconv.FormatBool(tcp.NS))
// 	TreeData.TreeIten = append(TreeData.TreeIten, rootItem)
// 	TreeData.TreeIten = append(TreeData.TreeIten, subItem)

// 	fmt.Println("    TCP ", tcp.SrcPort, tcp.DstPort)
// case layers.LayerTypeUDP:
// 	LayerTypeString = append(LayerTypeString, "UDP")
// 	rootItem := treeItem{}
// 	rootItem["UDP"] = append(rootItem["UDP"], "SourcePort: "+udp.SrcPort.String())
// 	rootItem["UDP"] = append(rootItem["UDP"], "DestinationPort: "+udp.DstPort.String())
// 	rootItem["UDP"] = append(rootItem["UDP"], "Length: "+strconv.Itoa(int(udp.Length))+" bytes")
// 	rootItem["UDP"] = append(rootItem["UDP"], "Payload: "+string(udp.Payload))
// 	TreeData.TreeIten = append(TreeData.TreeIten, rootItem)
// 	// TreeData.TreeIten = append(TreeData.TreeIten, subItem)
// 	fmt.Println("    UDP ", udp.SrcPort, udp.DstPort)
// case layers.LayerTypeARP:
// 	LayerTypeString = append(LayerTypeString, "ARP")

// 	rootItem := treeItem{}
// 	rootItem["ARP"] = append(rootItem["ARP"], "ProtocolType: "+strconv.Itoa(int(arp.Protocol)))
// 	rootItem["ARP"] = append(rootItem["ARP"], "HardwareSize: "+strconv.Itoa(int(arp.HwAddressSize)))
// 	rootItem["ARP"] = append(rootItem["ARP"], "OpCode: "+strconv.Itoa(int(arp.Operation)))
// 	ipSender := fmt.Sprintf("%d.%d.%d.%d", arp.SourceProtAddress[0], arp.SourceProtAddress[1],
// 		arp.SourceProtAddress[2], arp.SourceProtAddress[3])
// 	ipTarget := fmt.Sprintf("%d.%d.%d.%d", arp.DstProtAddress[0], arp.DstProtAddress[1],
// 		arp.DstProtAddress[2], arp.DstProtAddress[3])
// 	rootItem["ARP"] = append(rootItem["ARP"], "Sender MAC Address: "+string(arp.SourceHwAddress))
// 	rootItem["ARP"] = append(rootItem["ARP"], "Sender IP Address: "+string(arp.SourceProtAddress))
// 	rootItem["ARP"] = append(rootItem["ARP"], "Target MAC Address: "+ipTarget)
// 	rootItem["ARP"] = append(rootItem["ARP"], "Target IP Address: "+ipSender)
// 	TreeData.TreeIten = append(TreeData.TreeIten, rootItem)
// 	// TreeData.TreeIten = append(TreeData.TreeIten, subItem)

// 	fmt.Println("   ARP ", arp.SourceHwAddress, arp.DstHwAddress)
// 	// ipp := net.ParseIP(string(arp.SourceProtAddress[:]))

// case layers.LayerTypeIGMP:
// 	LayerTypeString = append(LayerTypeString, "IGMP")
// 	rootItem := treeItem{}
// 	rootItem["IGMP"] = append(rootItem["IGMP"], "Type: "+igmp.Type.String())
// 	rootItem["IGMP"] = append(rootItem["IGMP"], "Version: "+strconv.Itoa(int(igmp.Version)))
// 	rootItem["IGMP"] = append(rootItem["IGMP"], "Max Resp Time: "+igmp.MaxResponseTime.String())
// 	rootItem["IGMP"] = append(rootItem["IGMP"], "Checksum: "+strconv.Itoa(int(igmp.Checksum)))
// 	rootItem["IGMP"] = append(rootItem["IGMP"], "Multicast Address: "+igmp.GroupAddress.String())
// 	TreeData.TreeIten = append(TreeData.TreeIten, rootItem)
// 	// TreeData.TreeIten = append(TreeData.TreeIten, subItem)
// 	// fmt.Println("   IGMP ", igmp.GroupAddress)

// case layers.LayerTypeICMPv4:
// 	LayerTypeString = append(LayerTypeString, "ICMPv4")

// 	fmt.Println("    ICMPv4 ", icmpv4.Id, icmpv4.Seq)
// case layers.LayerTypeICMPv6:

// 	LayerTypeString = append(LayerTypeString, "ICMPv6")
// 	rootItem := treeItem{}
// 	rootItem["ICMPv6"] = append(rootItem["ICMPv6"], "Type: "+icmpv6.TypeCode.String())
// 	rootItem["ICMPv6"] = append(rootItem["ICMPv6"], "Code: "+strconv.Itoa(int(icmpv6.TypeCode)))
// 	// rootItem["ICMPv6"] = append(rootItem["ICMPv6"], "Multicast Address Recode Changed to execlude: "+icmpv6.)
// 	TreeData.TreeIten = append(TreeData.TreeIten, rootItem)
// 	// TreeData.TreeIten = append(TreeData.TreeIten, subItem)
// 	fmt.Println("    ICMPv6 ", icmpv6.TypeCode)

// case gopacket.LayerTypePayload:
// 	// rootItem := treeItem{}
// 	LayerTypeString = append(LayerTypeString, "PAYLOAD")
// 	// rootItem["PAYLOAD"] = append(rootItem["PAYLOAD"])
// 	subItem := treeItemByte{}
// 	subItem["PAYLOAD"] = payload
// 	// TreeData.TreeIten = append(TreeData.TreeIten, rootItem)
// 	TreeData.Data = subItem

// }
