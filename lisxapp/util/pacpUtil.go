package util

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// 用于存储device信息

func HasLayerType(typ gopacket.LayerType, typArr []gopacket.LayerType) bool {
	for _, r := range typArr {
		if int(typ)-int(r) == 0 {
			// fmt.Printf("**in HasLayerType1 %v in %v\n", typ, typArr)
			return true
		}
	}
	// fmt.Printf("**NOT in HasLayerType1 %v in %v\n", typ, typArr)
	return false
}

func NewDevInfo() *DevInfo {
	devices, err := pcap.FindAllDevs()

	if err != nil {
		log.Fatal(err)
	}
	DevInfoMap := &DevInfo{
		MapInfo: make(map[string]string, 10),
	}
	for _, device := range devices {
		DevInfoMap.MapInfo[device.Description] = device.Name
	}

	return DevInfoMap
}

// 得到设备
func (di *DevInfo) GetDev() []string {
	var res []string
	for k, _ := range di.MapInfo {
		res = append(res, k)
	}
	return res
}
func SetDev(dev string) {

	SelectedDev = Di.MapInfo[dev]

}

func packetCap(dev string, ctx context.Context, a fyne.App) {
	var (
		eth    layers.Ethernet
		ip4    layers.IPv4
		ip6    layers.IPv6
		tcp    layers.TCP
		arp    layers.ARP
		icmpv4 layers.ICMPv4
		icmpv6 layers.ICMPv6
		udp    layers.UDP

		igmp layers.IGMP

		igmpv1or2 layers.IGMPv1or2
		payload   gopacket.Payload
	)

	var snapshot_len int32 = 1024
	var promiscuous bool = false
	var err error
	var timeout time.Duration = 30 * time.Second
	var handle *pcap.Handle

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

	handle, err = pcap.OpenLive(dev, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)

	}
	// 添加对Filter的支持
	if Filter != "" {
		if err := handle.SetBPFFilter(Filter); err != nil {
			// ErrChan <- err
			w2 := a.NewWindow("error")
			w2.SetContent(widget.NewLabel("filter rule not supported"))
			w2.Resize(fyne.NewSize(100, 100))
			w2.Show()
			// dialog.ShowError(err, win)
			return
		}
	}

	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	i := 0
	for {
		select {
		case <-ctx.Done():
			// if IsStoped {
			fmt.Println("packetCap :cancel or Done")
			// if len(SwapChan) == 0 {
			// 	close(SwapChan)
			// }
			//if Restart {

			// close(SwapChan)
			//}

			handle.Close()
			return
			// break
			// }
		default:
			//  else {
			// i := 0
			if IsStoped {
				fmt.Println("stop error i: ", i)
				i++
			}

			// default:
			var res RowData

			packet, err := packetSource.NextPacket()
			if err == io.EOF {
				break
			} else if err != nil {
				log.Panicln("Error :", err)
				continue
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
			if err != nil {
				fmt.Println("decode error")
				continue
			}
			timecap := packet.Metadata().Timestamp
			timestr := timecap.Local().Format("2006-01-02 15:04:05")

			switch packetType {
			case layers.LayerTypeEthernet:
				res.No = strconv.Itoa(PacketIndex)
				res.Time = timestr
				res.Source = eth.SrcMAC.String()
				res.Destination = eth.DstMAC.String()
				res.Protocol = "ETHERNET"
				res.Length = strconv.Itoa(packet.Metadata().Length) + "bytes"

				res.Info = "Ethernet Packet"

			case layers.LayerTypeARP:
				res.No = strconv.Itoa(PacketIndex)
				res.Time = timestr
				res.Source = eth.SrcMAC.String()
				if strings.Compare(eth.DstMAC.String(), "ff:ff:ff:ff:ff:ff") == 0 {
					res.Destination = "Broadcast"
				} else {
					res.Destination = eth.DstMAC.String()
				}

				res.Protocol = "ARP"
				res.Length = strconv.Itoa(packet.Metadata().Length) + "bytes"
				ipSender := fmt.Sprintf("%d.%d.%d.%d", arp.SourceProtAddress[0], arp.SourceProtAddress[1],
					arp.SourceProtAddress[2], arp.SourceProtAddress[3])
				ipTarget := fmt.Sprintf("%d.%d.%d.%d", arp.DstProtAddress[0], arp.DstProtAddress[1],
					arp.DstProtAddress[2], arp.DstProtAddress[3])
				res.Info = fmt.Sprintf("who has %v ? Tell %v", ipSender, ipTarget)

			case layers.LayerTypeTCP:
				res.No = strconv.Itoa(PacketIndex)
				res.Time = timestr
				res.Protocol = "TCP"
				if HasLayerType(layers.LayerTypeIPv4, decoded) {

					res.Source = ip4.SrcIP.String()
					res.Destination = ip4.DstIP.String()
					res.Info = fmt.Sprintf("%d-->%d [**] Seq=%d Ack=%d Win=%d,Len=%d", tcp.SrcPort, tcp.DstPort, tcp.Seq, tcp.Ack, tcp.Window, ip4.Length-uint16(ip4.IHL))
				} else {
					res.Source = ip6.SrcIP.String()
					res.Destination = ip6.DstIP.String()
					res.Info = fmt.Sprintf("%d-->%d [**] Seq=%d Ack=%d Win=%d,Len=%d", tcp.SrcPort, tcp.DstPort, tcp.Seq, tcp.Ack, tcp.Window, ip6.Length-40)

				}

				res.Length = strconv.Itoa(packet.Metadata().Length) + "bytes"

			case layers.LayerTypeUDP:
				res.No = strconv.Itoa(PacketIndex)
				res.Time = timestr
				res.Protocol = "UDP"
				if HasLayerType(layers.LayerTypeIPv4, decoded) {

					res.Source = ip4.SrcIP.String()
					res.Destination = ip4.DstIP.String()
					res.Info = fmt.Sprintf("%d-->%d Len=%d", udp.SrcPort, udp.DstPort, ip4.Length-uint16(ip4.IHL))
				} else {
					res.Source = ip6.SrcIP.String()
					res.Destination = ip6.DstIP.String()
					res.Info = fmt.Sprintf("%d-->%d Len=%d", udp.SrcPort, udp.DstPort, ip6.Length-40)

				}

				res.Length = strconv.Itoa(packet.Metadata().Length) + "bytes"

			case layers.LayerTypeICMPv4:
				res.No = strconv.Itoa(PacketIndex)
				res.Time = timestr
				res.Protocol = "ICMPv4"
				codeType := icmpv6.TypeCode.Code()
				res.Info = fmt.Sprintf("icmp-type %d", codeType)
				res.Source = eth.SrcMAC.String()
				res.Destination = eth.DstMAC.String()
				res.Length = strconv.Itoa(packet.Metadata().Length) + "bytes"

			case layers.LayerTypeICMPv6:
				res.No = strconv.Itoa(PacketIndex)
				res.Time = timestr
				res.Protocol = "ICMPv6"
				codeType := icmpv6.TypeCode.Code()
				res.Info = fmt.Sprintf("icmp-type %d", codeType)
				res.Source = eth.SrcMAC.String()
				res.Destination = eth.DstMAC.String()
				res.Length = strconv.Itoa(packet.Metadata().Length) + "bytes"

			case layers.LayerTypeIGMP:
				res.No = strconv.Itoa(PacketIndex)
				res.Time = timestr
				res.Protocol = "IGMP"

				codeType := icmpv6.TypeCode.String()
				res.Info = fmt.Sprintf("iGmp-type %s", codeType)
				if HasLayerType(layers.LayerTypeIPv4, decoded) {

					res.Source = ip4.SrcIP.String()
					res.Destination = ip4.DstIP.String()
					// res.Info = fmt.Sprintf("%d→%d Len=%d", udp.SrcPort, udp.DstPort, ip4.Length-uint16(ip4.IHL))
				} else {
					res.Source = ip6.SrcIP.String()
					res.Destination = ip6.DstIP.String()
					// res.Info = fmt.Sprintf("%d→%d Len=%d", udp.SrcPort, udp.DstPort, ip6.Length-40)

				}
				res.Length = strconv.Itoa(packet.Metadata().Length) + " bytes"

			}
			PacketMap[PacketIndex] = packet
			PacketIndex++

			SwapChan <- res
			// fmt.Printf("%p\n", &SwapChan)
		}

	}

}
