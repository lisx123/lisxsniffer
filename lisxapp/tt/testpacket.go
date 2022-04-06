package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var PacketMap = make(map[int]gopacket.Packet)

type tableContent1 struct {
	No          string
	Time        string
	Source      string
	Destination string
	Protocol    string
	Length      string
	Info        string
}

var (
	eth    layers.Ethernet
	ip4    layers.IPv4
	ip6    layers.IPv6
	tcp    layers.TCP
	arp    layers.ARP
	icmpv4 layers.ICMPv4
	icmpv6 layers.ICMPv6
	udp    layers.UDP
	igmp   layers.IGMP
	// igmpv3    layers.IGMPv3GroupRecord
	igmpv1or2 layers.IGMPv1or2
	payload   gopacket.Payload

	// payload   gopacket.Payload
)

func HasLayerType1(typ gopacket.LayerType, typArr []gopacket.LayerType) bool {

	for _, r := range typArr {
		if int(typ)-int(r) == 0 {
			// fmt.Printf("**in HasLayerType1 %v in %v\n", typ, typArr)
			return true
		}
	}
	// fmt.Printf("**NOT in HasLayerType1 %v in %v\n", typ, typArr)
	return false
}
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
	// 打开某一网络设备
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	// Use the handle as a packet source to process all packets
	index := 0

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
	// // 使用map类型是不是能级析出一个packet中包含哪些协议
	decoder := dlc.LayersDecoder(layers.LayerTypeEthernet, gopacket.NilDecodeFeedback)
	decoded := make([]gopacket.LayerType, 0, 20)
	// parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp,
	// 	&udp, &igmp, &arp)
	// decoded := []gopacket.LayerType{}
	var file *os.File
	var err1 error
	filename := "res1.txt"
	// if _, err1 = os.Stat(filename); err1 == nil {
	// 	file, err1 = os.Open(filename)
	// }
	file, err1 = os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0666)
	if err1 != nil {
		log.Fatal("crate ", filename, "error", err)
	}
	// if os.IsNotExist(err1) {
	// 	log.Fatal("crate ", filename, "error", err1)
	// 	file, err1 = os.Create(filename)
	// 	if err1 != nil {
	// 		log.Fatal("create error")
	// 	}
	// }

	defer file.Close()
	writer := bufio.NewWriter(file)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	// var res tableContent1
	for {
		var res tableContent1
		packet, err := packetSource.NextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Panicln("Error :", err)
			continue
		}

		if index == 2000 {
			handle.Close()

			return
		}

		it, err := decoder(packet.Data(), &decoded)
		packetType := decoded[len(decoded)-1]
		if packetType == gopacket.LayerTypePayload {
			packetType = decoded[len(decoded)-2]
		}
		if it != gopacket.LayerTypeZero {
			fmt.Fprintf(os.Stderr, "unknown layer type: %v\n", it)
			continue

		}

		index = index + 1
		PacketMap[index] = packet

		// tableRow := handlePackaetSuitTable1(index, packet, dlc)
		// fmt.Println("      ppacket.Metadata().CaptureInfo %v\n", packet.Metadata().AncillaryData)
		// it, err := decoder(packet.Data(), &decoded)

		// fmt.Printf("%v\n", tableRow)

		switch packetType {
		case layers.LayerTypeARP:
			continue
			// res.No = strconv.Itoa(index)
			// res.Time = "0"
			// res.Source = eth.SrcMAC.String()
			// if strings.Compare(eth.DstMAC.String(), "ff:ff:ff:ff:ff:ff") == 0 {
			// 	res.Destination = "Broadcast"
			// } else {
			// 	res.Destination = eth.DstMAC.String()
			// }

			// res.Protocol = "ARP"
			// res.Length = strconv.Itoa(packet.Metadata().Length) + "bytes"
			// ipSender := fmt.Sprintf("%d.%d.%d.%d", arp.SourceProtAddress[0], arp.SourceProtAddress[1],
			// 	arp.SourceProtAddress[2], arp.SourceProtAddress[3])
			// ipTarget := fmt.Sprintf("%d.%d.%d.%d", arp.DstProtAddress[0], arp.DstProtAddress[1],
			// 	arp.DstProtAddress[2], arp.DstProtAddress[3])
			// res.Info = fmt.Sprintf("who has %v ? Tell %v", ipSender, ipTarget)

		case layers.LayerTypeTCP:
			res.No = strconv.Itoa(index)
			res.Time = "0"
			res.Protocol = "TCP"
			if HasLayerType1(layers.LayerTypeIPv4, decoded) {

				res.Source = ip4.SrcIP.String()
				res.Destination = ip4.DstIP.String()
				res.Info = fmt.Sprintf("%d→%d [%s] Seq=%d Ack=%d Win=%d,Len=%d", tcp.SrcPort, tcp.DstPort, tcp.Ack, tcp.Window, ip4.Length-uint16(ip4.IHL))
			} else {
				res.Source = ip6.SrcIP.String()
				res.Destination = ip6.DstIP.String()
				res.Info = fmt.Sprintf("%d→%d [%s] Seq=%d Ack=%d Win=%d,Len=%d", tcp.SrcPort, tcp.DstPort, tcp.Ack, tcp.Window, ip6.Length-40)

			}
			applayer := tcp.Payload
			if applayer != nil {
				apppayload := string(applayer)
				if strings.HasPrefix(apppayload, "GET") || strings.HasPrefix(apppayload, "POST") {
					reg := regexp.MustCompile(`(?s)(GET|POST) (.*?) HTTP.*Host: (.*?)\n`)
					if reg == nil {
						fmt.Println("mustcomplie err")
					} else {
						result := reg.FindStringSubmatch(apppayload)

						if len(result) == 4 {
							strings.TrimSpace(result[2])
							url := "http://" + strings.TrimSpace(result[3]) + strings.TrimSpace(result[2])
							fmt.Println("url:", url)
							fmt.Println("host:", result[3])
						} else {
							fmt.Println("error===================")
						}

					}
				}
			}

			res.Length = strconv.Itoa(packet.Metadata().Length) + "bytes"

		case layers.LayerTypeUDP:
			res.No = strconv.Itoa(index)
			res.Time = "0"
			res.Protocol = "UDP"
			if HasLayerType1(layers.LayerTypeIPv4, decoded) {

				res.Source = ip4.SrcIP.String()
				res.Destination = ip4.DstIP.String()
				res.Info = fmt.Sprintf("%d→%d Len=%d", udp.SrcPort, udp.DstPort, ip4.Length-uint16(ip4.IHL))
			} else {
				res.Source = ip6.SrcIP.String()
				res.Destination = ip6.DstIP.String()
				res.Info = fmt.Sprintf("%d→%d Len=%d", udp.SrcPort, udp.DstPort, ip6.Length-40)

			}
			applayer := udp.Payload //packet.ApplicationLayer()
			if applayer != nil {
				apppayload := string(applayer)
				if strings.HasPrefix(apppayload, "GET") || strings.HasPrefix(apppayload, "POST") {
					reg := regexp.MustCompile(`(?s)(GET|POST) (.*?) HTTP.*Host: (.*?)\n`)
					if reg == nil {
						fmt.Println("mustcomplie err")
					} else {
						result := reg.FindStringSubmatch(apppayload)

						if len(result) == 4 {
							strings.TrimSpace(result[2])
							url := "http://" + strings.TrimSpace(result[3]) + strings.TrimSpace(result[2])
							fmt.Println("url:", url)
							fmt.Println("host:", result[3])
							res.Protocol = "HTTP"
							res.Info = fmt.Sprintf("url:%s ,port:%s ", url, result[3])
						} else {
							fmt.Println("error===================")
						}

					}
				}
			}
			// _, _ = writer.WriteString(result)

			res.Length = strconv.Itoa(packet.Metadata().Length) + "bytes"

		case layers.LayerTypeICMPv4:
			continue
			// res.No = strconv.Itoa(index)
			// res.Time = "0"
			// res.Protocol = "ICMPv4"
			// codeType := icmpv6.TypeCode.Code()
			// res.Info = fmt.Sprintf("icmp-type %d", codeType)
			// res.Source = eth.SrcMAC.String()
			// res.Destination = eth.DstMAC.String()
			// res.Length = strconv.Itoa(packet.Metadata().Length) + "bytes"

		case layers.LayerTypeICMPv6:
			continue
			// res.No = strconv.Itoa(index)
			// res.Time = "0"
			// res.Protocol = "ICMPv6"
			// codeType := icmpv6.TypeCode.Code()
			// res.Info = fmt.Sprintf("icmp-type %d", codeType)
			// res.Source = eth.SrcMAC.String()
			// res.Destination = eth.DstMAC.String()
			// res.Length = strconv.Itoa(packet.Metadata().Length) + " bytes"

		case layers.LayerTypeIGMP:
			continue
			// res.No = strconv.Itoa(index)
			// res.Time = "0"
			// if igmp.Type == 0x16 || igmp.Type == 0x12 {
			// 	res.Protocol = "IGMPv2"
			// }
			// if igmp.Type == 0x17 {
			// 	res.Protocol = "Leave Group"
			// }

			// if igmp.Type == 0x22 {
			// 	res.Protocol = "IGMPv3"
			// }
			// res.Protocol = "IGMP"

			// codeType := icmpv6.TypeCode.String()
			// res.Info = fmt.Sprintf("iGmp-type %s", codeType)
			// if HasLayerType1(layers.LayerTypeIPv4, decoded) {

			// 	res.Source = ip4.SrcIP.String()
			// 	res.Destination = ip4.DstIP.String()
			// 	// res.Info = fmt.Sprintf("%d→%d Len=%d", udp.SrcPort, udp.DstPort, ip4.Length-uint16(ip4.IHL))
			// } else {
			// 	res.Source = ip6.SrcIP.String()
			// 	res.Destination = ip6.DstIP.String()
			// 	// res.Info = fmt.Sprintf("%d→%d Len=%d", udp.SrcPort, udp.DstPort, ip6.Length-40)

			// }
			// // res.Source = eth.SrcMAC.String()
			// // res.Destination = eth.DstMAC.String()
			// res.Length = strconv.Itoa(packet.Metadata().Length) + "bytes"

		}

		// test := res == tableContent1{}
		// if test {
		// 	tes := fmt.Sprintf("empty res %v", decoded)
		// 	res.Info = tes
		// }
		stringRes := fmt.Sprintf("res : %v\n", res)
		_, _ = writer.WriteString(stringRes)

		// fmt.Printf("Decoding Packet %d: support layers:%v \n", index, decoded)
		// fmt.Println("        ", packetType)
		// fmt.Println("        res: ", stringRes)
		// fmt.Println("        packetlength: ", packet.Metadata().CaptureLength)
	}

}

// 应该没用了
// func handlePackaetSuitTable1(index int, packet gopacket.Packet, dlc gopacket.DecodingLayerContainer) *tableContent1 {

// 	decoder := dlc.LayersDecoder(layers.LayerTypeEthernet, gopacket.NilDecodeFeedback)
// 	decoded := make([]gopacket.LayerType, 0, 20)
// 	var res tableContent1

// 	it, _ := decoder(packet.Data(), &decoded)

// 	// 如果不支持packet的类型，就返回错误
// 	if it != gopacket.LayerTypeZero {
// 		fmt.Fprintf(os.Stderr, "unknown layer type: %v\n", it)
// 		return nil
// 	}
// 	packetType := decoded[len(decoded)-1]
// 	PacketMap[index] = packet
// 	// if packetType == gopacket.LayerTypePayload {
// 	// 	packetType = decoded[len(decoded)-2]
// 	// }
// 	fmt.Println(packetType)

// res.No = strconv.Itoa(index)
// switch packetType {
// case layers.LayerTypeARP:

// 	res.Time = "0"
// 	res.Source = eth.SrcMAC.String()
// 	if strings.Compare(eth.DstMAC.String(), "0 0 0 0 0 0") == 0 {
// 		res.Destination = "Broadcast"
// 	}
// 	res.Destination = eth.DstMAC.String()
// 	res.Protocol = "ARP"
// 	res.Length = strconv.Itoa(packet.Metadata().Length) + "bytes"
// 	ipSender := fmt.Sprintf("%d.%d.%d.%d", arp.SourceProtAddress[0], arp.SourceProtAddress[1],
// 		arp.SourceProtAddress[2], arp.SourceProtAddress[3])
// 	ipTarget := fmt.Sprintf("%d.%d.%d.%d", arp.DstProtAddress[0], arp.DstProtAddress[1],
// 		arp.DstProtAddress[2], arp.DstProtAddress[3])
// 	res.Info = fmt.Sprintf("who has %s ? Tell %s", &ipSender, &ipTarget)

// case layers.LayerTypeTCP:

// 	res.Time = "0"
// 	res.Protocol = "TCP"
// 	if HasLayerType1(layers.LayerTypeIPv4, decoded) {

// 		res.Source = ip4.SrcIP.String()
// 		res.Destination = ip4.DstIP.String()
// 		res.Info = fmt.Sprintf("%d→%d [%s] Seq=%d Ack=%d Win=%d,Len=%d", tcp.SrcPort, tcp.DstPort, tcp.Ack, tcp.Window, ip4.Length-uint16(ip4.IHL))
// 	} else {
// 		res.Source = ip6.SrcIP.String()
// 		res.Destination = ip6.DstIP.String()
// 		res.Info = fmt.Sprintf("%d→%d [%s] Seq=%d Ack=%d Win=%d,Len=%d", tcp.SrcPort, tcp.DstPort, tcp.Ack, tcp.Window, ip6.Length-40)

// 	}

// 	res.Length = strconv.Itoa(packet.Metadata().Length) + "bytes"

// case layers.LayerTypeUDP:

// 	res.Time = "0"
// 	res.Protocol = "UDP"
// 	if HasLayerType1(layers.LayerTypeIPv4, decoded) {

// 		res.Source = ip4.SrcIP.String()
// 		res.Destination = ip4.DstIP.String()
// 		res.Info = fmt.Sprintf("%d→%d [%s] Seq=%d Ack=%d Win=%d,Len=%d", udp.SrcPort, udp.DstPort, ip4.Length-uint16(ip4.IHL))
// 	} else {
// 		res.Source = ip6.SrcIP.String()
// 		res.Destination = ip6.DstIP.String()
// 		res.Info = fmt.Sprintf("%d→%d [%s] Seq=%d Ack=%d Win=%d,Len=%d", udp.SrcPort, udp.DstPort, ip6.Length-40)

// 	}

// 	res.Length = strconv.Itoa(packet.Metadata().Length) + "bytes"

// case layers.LayerTypeICMPv4:

// 	res.Time = "0"
// 	res.Protocol = "ICMPv4"
// 	codeType := icmpv6.TypeCode.Code()
// 	res.Info = fmt.Sprintf("icmp-type %d", codeType)
// 	res.Source = eth.SrcMAC.String()
// 	res.Destination = eth.DstMAC.String()
// 	res.Length = strconv.Itoa(packet.Metadata().Length) + "bytes"

// case layers.LayerTypeICMPv6:

// 	res.Time = "0"
// 	res.Protocol = "ICMPv6"
// 	codeType := icmpv6.TypeCode.Code()
// 	res.Info = fmt.Sprintf("icmp-type %d", codeType)
// 	res.Source = eth.SrcMAC.String()
// 	res.Destination = eth.DstMAC.String()
// 	res.Length = strconv.Itoa(packet.Metadata().Length) + "bytes"

// case layers.LayerTypeIGMP:

// 	res.Time = "0"
// 	if igmp.Type == 0x16 || igmp.Type == 0x12 {
// 		res.Protocol = "IGMPv2"
// 	}
// 	if igmp.Type == 0x17 {
// 		res.Protocol = "Leave Group"
// 	}

// 	if igmp.Type == 0x22 {
// 		res.Protocol = "IGMPv3"
// 	}
// 	codeType := icmpv6.TypeCode.Code()
// 	res.Info = fmt.Sprintf("icmp-type %d", codeType)
// 	res.Source = eth.SrcMAC.String()
// 	res.Destination = eth.DstMAC.String()
// 	res.Length = strconv.Itoa(packet.Metadata().Length) + "bytes"

// }

// 	return &res
// }

// stringRes := fmt.Sprintf("res : %v\n", res)
// fmt.Printf("Decoding Packet %d: support layers:%v \n", index, decoded)
// fmt.Println("        ", packetType)
// fmt.Println("        res: ", stringRes)
// fmt.Println("        packength: ", packet.Metadata().CaptureLength)
//对packet数据进行解析
// 添加保存信息 点击结束1按钮后跳出一个弹框，，设置保存信息为1，然后在这恶鬼函数中调用保存信息
// if startCap == 1 {
// tableRow := handlePackaetSuitTable(index, packet)

// var rowStringArr []string
// // tableRowDataStruct := dataChan
// // fmt.Printf("%v\n", tableRowDataStruct)
// rowStringArr = append(rowStringArr, res.No)
// rowStringArr = append(rowStringArr, res.Time)
// rowStringArr = append(rowStringArr, res.Source)
// rowStringArr = append(rowStringArr, res.Destination)
// rowStringArr = append(rowStringArr, res.Protocol)
// rowStringArr = append(rowStringArr, res.Length)
// rowStringArr = append(rowStringArr, res.Info)
