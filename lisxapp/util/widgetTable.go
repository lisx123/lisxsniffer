package util

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func DataTable(mainwindow fyne.Window) *widget.Table {

	tbl := &widget.Table{}
	tbl.Length = func() (int, int) {
		return len(Rowdatas) + 1, len(PacketDataCols)
	}
	tbl.CreateCell = func() fyne.CanvasObject {
		return widget.NewLabel("--")
	}

	tbl.UpdateCell = func(cell widget.TableCellID, template fyne.CanvasObject) {

		if cell.Row == 0 {
			label := template.(*widget.Label)
			label.Alignment = fyne.TextAlignCenter
			label.TextStyle = fyne.TextStyle{Bold: true}

			label.SetText(PacketDataCols[cell.Col])
		} else {
			// fmt.Println(cell.Row)
			lbl := template.(*widget.Label)
			lbl.Wrapping = fyne.TextWrapOff
			lbl.Alignment = fyne.TextAlignLeading

			lbl.SetText(Rowdatas[cell.Row-1][cell.Col])
		}

	}

	// 这里更新树形结构和数据二进制展示
	tbl.OnSelected = func(cell widget.TableCellID) {
		// 这里有一个越界的BUG，停止后点最后一个，程序会退出
		if cell.Row < 0 || cell.Row > len(Rowdatas) { // 1st col is header
			fmt.Println("*-> Row out of limits")
			return
		}
		if cell.Col < 0 || cell.Col >= len(PacketDataCols) {
			fmt.Println("*-> Column out of limits")
			return
		}
		Onclicked = true
		tableRow := cell.Row
		if tableRow == 0 {
			return
		}

		fmt.Println("=====", tableRow)
		selectPacIdx, _ := strconv.Atoi(Rowdatas[tableRow-1][0])
		selectPacket := PacketMap[selectPacIdx]
		treeres := GetTreeData(selectPacket, selectPacIdx)
		TreeDataSwapChan <- treeres
		PacketDataShowChan <- treeres.Data

	}

	refWidth := widget.NewLabel("tblOpts.RefWidthsfg eryge ").MinSize().Width
	// Set Column widths
	colWidth := []int{20, 100, 100, 100, 45, 40, 130}
	for k, v := range colWidth {
		tbl.SetColumnWidth(k, float32(v)/100.0*refWidth)
	}
	go func() {

		for { //res := range SwapChan
			if len(SwapChan) == 0 {
				time.Sleep(2 * time.Second)
			} else {
				// if IsStoped {
				// 	break
				// }
				res := <-SwapChan

				rowStringArr := []string{}
				// fmt.Printf("%v\n", tableRowDataStruct)
				rowStringArr = append(rowStringArr, res.No)
				rowStringArr = append(rowStringArr, res.Time)
				rowStringArr = append(rowStringArr, res.Source)
				rowStringArr = append(rowStringArr, res.Destination)
				rowStringArr = append(rowStringArr, res.Protocol)
				rowStringArr = append(rowStringArr, res.Length)
				rowStringArr = append(rowStringArr, res.Info)
				Rowdatas = append(Rowdatas, rowStringArr)

				tbl.Refresh()

			}

		}

	}()

	return tbl

}

func GetTreeData(packet gopacket.Packet, idx int) TreeDataStruct {

	TreeData := TreeDataStruct{
		PacketIndex: idx,
		TreeIten:    make(map[string][]string, 10),
		Data:        make([]byte, 10),
	}
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
	_, err := decoder(packet.Data(), &decoded)
	var LayerTypeString []string
	for _, typ := range decoded {

		switch typ {

		case layers.LayerTypeEthernet:
			LayerTypeString = append(LayerTypeString, "ETH")
			// TreeData.TreeIten := treeItem{}
			TreeData.TreeIten["ETH"] = append(TreeData.TreeIten["ETH"], "Source")
			TreeData.TreeIten["ETH"] = append(TreeData.TreeIten["ETH"], "Destination")
			// subItem := treeItem{}
			TreeData.TreeIten["Source"] = append(TreeData.TreeIten["Source"], eth.SrcMAC.String())
			TreeData.TreeIten["Destination"] = append(TreeData.TreeIten["Destination"], eth.DstMAC.String())

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

			// fmt.Println("    IP4 ", ip4.SrcIP, ip4.DstIP)

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
			// fmt.Println("    IP6 ", ip6.SrcIP, ip6.DstIP)
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

		case layers.LayerTypeUDP:
			LayerTypeString = append(LayerTypeString, "UDP")

			TreeData.TreeIten["UDP"] = append(TreeData.TreeIten["UDP"], "SourcePort: "+udp.SrcPort.String())
			TreeData.TreeIten["UDP"] = append(TreeData.TreeIten["UDP"], "DestinationPort: "+udp.DstPort.String())
			TreeData.TreeIten["UDP"] = append(TreeData.TreeIten["UDP"], "Length: "+strconv.Itoa(int(udp.Length))+" bytes")

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

		case layers.LayerTypeIGMP:
			LayerTypeString = append(LayerTypeString, "IGMP")

			TreeData.TreeIten["IGMP"] = append(TreeData.TreeIten["IGMP"], "Type: "+igmp.Type.String())
			TreeData.TreeIten["IGMP"] = append(TreeData.TreeIten["IGMP"], "Version: "+strconv.Itoa(int(igmp.Version)))
			TreeData.TreeIten["IGMP"] = append(TreeData.TreeIten["IGMP"], "Max Resp Time: "+igmp.MaxResponseTime.String())
			TreeData.TreeIten["IGMP"] = append(TreeData.TreeIten["IGMP"], "Checksum: "+strconv.Itoa(int(igmp.Checksum)))
			TreeData.TreeIten["IGMP"] = append(TreeData.TreeIten["IGMP"], "Multicast Address: "+igmp.GroupAddress.String())

		case layers.LayerTypeICMPv4:
			LayerTypeString = append(LayerTypeString, "ICMPv4")

			fmt.Println("    ICMPv4 ", icmpv4.Id, icmpv4.Seq)
		case layers.LayerTypeICMPv6:

			LayerTypeString = append(LayerTypeString, "ICMPv6")

			TreeData.TreeIten["ICMPv6"] = append(TreeData.TreeIten["ICMPv6"], "Type: "+icmpv6.TypeCode.String())
			TreeData.TreeIten["ICMPv6"] = append(TreeData.TreeIten["ICMPv6"], "Code: "+strconv.Itoa(int(icmpv6.TypeCode)))

		case gopacket.LayerTypePayload:
			// TreeData.TreeIten := treeItem{}
			LayerTypeString = append(LayerTypeString, "PAYLOAD")
			TreeData.TreeIten["PAYLOAD"] = append(TreeData.TreeIten["PAYLOAD"], hex.EncodeToString(payload))

		}

	}

	TreeData.TreeIten[""] = LayerTypeString

	TreeData.Data = packet.Data()

	if err != nil {
		fmt.Println("  Error encountered:", err)

	}
	return TreeData
}
