package main

import (
	"app1/util"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// 用于存储device信息
type DevInfo struct {
	MapInfo map[string]string
}

var ExitFlag = 0
var Di = *NewDevInfo()
var SelectedDev string

var demAtt = make([][]string, 0)
var rowStringArr []string

// 对选择的设备进行抓取

type tableContent struct {
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

	igmp layers.IGMP

	igmpv1or2 layers.IGMPv1or2
	payload   gopacket.Payload
)
var snapshot_len int32 = 1024
var promiscuous bool = false
var err error
var timeout time.Duration = 30 * time.Second
var handle *pcap.Handle
var startCap int = 0

// 初始化设备列表
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

	return

}

func packetCap(dev string, dataChan chan tableContent) {

	index := 0

	handle, err = pcap.OpenLive(dev, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)

	}
	defer handle.Close()
	// fmt.Println("in go routine exitflag=", ExitFlag)

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

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {

		var res tableContent
		packet, err := packetSource.NextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Panicln("Error :", err)
			continue
		}
		index = index + 1
		if index == 1000 {
			handle.Close()
			close(dataChan)
			fmt.Println("go exit")
			return
		}
		// fmt.Println("in go routine for loop exitflag=", ExitFlag)
		it, err := decoder(packet.Data(), &decoded)
		packetType := decoded[len(decoded)-1]
		if packetType == gopacket.LayerTypePayload {
			packetType = decoded[len(decoded)-2]
		}
		if it != gopacket.LayerTypeZero {
			fmt.Fprintf(os.Stderr, "unknown layer type: %v\n", it)
			continue

		}

		res.No = strconv.Itoa(index)
		switch packetType {
		case layers.LayerTypeARP:

			res.Time = "0"
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

			res.Time = "0"
			res.Protocol = "TCP"
			if HasLayerType(layers.LayerTypeIPv4, decoded) {

				res.Source = ip4.SrcIP.String()
				res.Destination = ip4.DstIP.String()
				res.Info = fmt.Sprintf("%d→%d [%s] Seq=%d Ack=%d Win=%d,Len=%d", tcp.SrcPort, tcp.DstPort, tcp.Ack, tcp.Window, ip4.Length-uint16(ip4.IHL))
			} else {
				res.Source = ip6.SrcIP.String()
				res.Destination = ip6.DstIP.String()
				res.Info = fmt.Sprintf("%d→%d [%s] Seq=%d Ack=%d Win=%d,Len=%d", tcp.SrcPort, tcp.DstPort, tcp.Ack, tcp.Window, ip6.Length-40)

			}

			res.Length = strconv.Itoa(packet.Metadata().Length) + "bytes"

		case layers.LayerTypeUDP:

			res.Time = "0"
			res.Protocol = "UDP"
			if HasLayerType(layers.LayerTypeIPv4, decoded) {

				res.Source = ip4.SrcIP.String()
				res.Destination = ip4.DstIP.String()
				res.Info = fmt.Sprintf("%d→%d [%s] Seq=%d Ack=%d Win=%d,Len=%d", udp.SrcPort, udp.DstPort, ip4.Length-uint16(ip4.IHL))
			} else {
				res.Source = ip6.SrcIP.String()
				res.Destination = ip6.DstIP.String()
				res.Info = fmt.Sprintf("%d→%d [%s] Seq=%d Ack=%d Win=%d,Len=%d", udp.SrcPort, udp.DstPort, ip6.Length-40)

			}

			res.Length = strconv.Itoa(packet.Metadata().Length) + "bytes"

		case layers.LayerTypeICMPv4:

			res.Time = "0"
			res.Protocol = "ICMPv4"
			codeType := icmpv6.TypeCode.Code()
			res.Info = fmt.Sprintf("icmp-type %d", codeType)
			res.Source = eth.SrcMAC.String()
			res.Destination = eth.DstMAC.String()
			res.Length = strconv.Itoa(packet.Metadata().Length) + "bytes"

		case layers.LayerTypeICMPv6:

			res.Time = "0"
			res.Protocol = "ICMPv6"
			codeType := icmpv6.TypeCode.Code()
			res.Info = fmt.Sprintf("icmp-type %d", codeType)
			res.Source = eth.SrcMAC.String()
			res.Destination = eth.DstMAC.String()
			res.Length = strconv.Itoa(packet.Metadata().Length) + "bytes"

		case layers.LayerTypeIGMP:

			res.Time = "0"
			if igmp.Type == 0x16 || igmp.Type == 0x12 {
				res.Protocol = "IGMPv2"
			}
			if igmp.Type == 0x17 {
				res.Protocol = "Leave Group"
			}

			if igmp.Type == 0x22 {
				res.Protocol = "IGMPv3"
			}
			codeType := icmpv6.TypeCode.Code()
			res.Info = fmt.Sprintf("icmp-type %d", codeType)
			res.Source = eth.SrcMAC.String()
			res.Destination = eth.DstMAC.String()
			res.Length = strconv.Itoa(packet.Metadata().Length) + " bytes"

		}
		stringRes := fmt.Sprintf("res : %v\n", res)

		fmt.Printf("Decoding Packet %d: support layers:%v \n", index, decoded)
		fmt.Println("        ", packetType)
		fmt.Println("        res: ", stringRes)
		fmt.Println("        packength: ", packet.Metadata().CaptureLength)

		//对packet数据进行解析
		// 添加保存信息 点击结束1按钮后跳出一个弹框，，设置保存信息为1，然后在这恶鬼函数中调用保存信息

		// if startCap == 1 {
		// tableRow := handlePackaetSuitTable(index, packet)

		fmt.Println("chain kaishi")
		dataChan <- res
		// tableShowData <- *tableRow
		fmt.Println("chain jieshu")
		index++

		go func() {
			fmt.Println("11111111111")
			tableRowDataStruct := <-dataChan
			// tableRowDataStruct := dataChan
			fmt.Printf("%v\n", tableRowDataStruct)
			rowStringArr = append(rowStringArr, tableRowDataStruct.No)
			rowStringArr = append(rowStringArr, tableRowDataStruct.Time)
			rowStringArr = append(rowStringArr, tableRowDataStruct.Source)
			rowStringArr = append(rowStringArr, tableRowDataStruct.Destination)
			rowStringArr = append(rowStringArr, tableRowDataStruct.Protocol)
			rowStringArr = append(rowStringArr, tableRowDataStruct.Length)
			rowStringArr = append(rowStringArr, tableRowDataStruct.Info)
			demAtt = append(demAtt, rowStringArr)
			return

		}()

		// }

		// if packetIndex == 100 {
		// 	return
		// }

	}

}

// func initDecoder() gopacket.DecodingLayerContainer {
// 	dlc := gopacket.DecodingLayerContainer(gopacket.DecodingLayerArray(nil))
// 	dlc = dlc.Put(&eth)
// 	dlc = dlc.Put(&ip4)
// 	dlc = dlc.Put(&ip6)
// 	dlc = dlc.Put(&tcp)
// 	dlc = dlc.Put(&udp)
// 	dlc = dlc.Put(&icmpv4)
// 	dlc = dlc.Put(&icmpv6)
// 	dlc = dlc.Put(&igmp)
// 	dlc = dlc.Put(&arp)
// 	// dlc = dlc.Put(&payload)
// 	dlc = dlc.Put(&igmpv1or2)

// 	return dlc
// }
func newTableContent(No string, Length string, Time, Source, Destination, Protocol, Info string) *tableContent {
	return &tableContent{
		No:          No,
		Time:        Time,
		Source:      Source,
		Destination: Destination,
		Protocol:    Protocol,
		Info:        Info,
		Length:      Length,
	}
}
func HasLayerType(typ gopacket.LayerType, typArr []gopacket.LayerType) bool {
	for r := range typArr {
		if (int(typ) - r) == 0 {
			return true
		}
	}
	return false
}
func handlePackaetSuitTable(index int, packet gopacket.Packet) *tableContent {
	dlc := initDecoder()
	decoder := dlc.LayersDecoder(layers.LayerTypeEthernet, gopacket.NilDecodeFeedback)
	decoded := make([]gopacket.LayerType, 0, 20)
	var res tableContent

	it, _ := decoder(packet.Data(), &decoded)

	// 如果不支持packet的类型，就返回错误
	if it != gopacket.LayerTypeZero {
		fmt.Fprintf(os.Stderr, "unknown layer type: %v\n", it)
		return nil
	}
	packetType := decoded[len(decoded)-1]
	// if packetType == gopacket.LayerTypePayload {
	// 	packetType = decoded[len(decoded)-2]
	// }

	res.No = strconv.Itoa(index)
	switch packetType {
	case layers.LayerTypeARP:

		res.Time = "0"
		res.Source = eth.SrcMAC.String()
		if strings.Compare(eth.DstMAC.String(), "0 0 0 0 0 0") == 0 {
			res.Destination = "Broadcast"
		}
		res.Destination = eth.DstMAC.String()
		res.Protocol = "ARP"
		res.Length = strconv.Itoa(packet.Metadata().Length) + "bytes"
		ipSender := fmt.Sprintf("%d.%d.%d.%d", arp.SourceProtAddress[0], arp.SourceProtAddress[1],
			arp.SourceProtAddress[2], arp.SourceProtAddress[3])
		ipTarget := fmt.Sprintf("%d.%d.%d.%d", arp.DstProtAddress[0], arp.DstProtAddress[1],
			arp.DstProtAddress[2], arp.DstProtAddress[3])
		res.Info = fmt.Sprintf("who has %s ? Tell %s", &ipSender, &ipTarget)

	case layers.LayerTypeTCP:

		res.Time = "0"
		res.Protocol = "TCP"
		if HasLayerType(layers.LayerTypeIPv4, decoded) {

			res.Source = ip4.SrcIP.String()
			res.Destination = ip4.DstIP.String()
			res.Info = fmt.Sprintf("%d→%d [%s] Seq=%d Ack=%d Win=%d,Len=%d", tcp.SrcPort, tcp.DstPort, tcp.Ack, tcp.Window, ip4.Length-uint16(ip4.IHL))
		} else {
			res.Source = ip6.SrcIP.String()
			res.Destination = ip6.DstIP.String()
			res.Info = fmt.Sprintf("%d→%d [%s] Seq=%d Ack=%d Win=%d,Len=%d", tcp.SrcPort, tcp.DstPort, tcp.Ack, tcp.Window, ip6.Length-40)

		}

		res.Length = strconv.Itoa(packet.Metadata().Length) + "bytes"

	case layers.LayerTypeUDP:

		res.Time = "0"
		res.Protocol = "UDP"
		if HasLayerType(layers.LayerTypeIPv4, decoded) {

			res.Source = ip4.SrcIP.String()
			res.Destination = ip4.DstIP.String()
			res.Info = fmt.Sprintf("%d→%d [%s] Seq=%d Ack=%d Win=%d,Len=%d", udp.SrcPort, udp.DstPort, ip4.Length-uint16(ip4.IHL))
		} else {
			res.Source = ip6.SrcIP.String()
			res.Destination = ip6.DstIP.String()
			res.Info = fmt.Sprintf("%d→%d [%s] Seq=%d Ack=%d Win=%d,Len=%d", udp.SrcPort, udp.DstPort, ip6.Length-40)

		}

		res.Length = strconv.Itoa(packet.Metadata().Length) + "bytes"

	case layers.LayerTypeICMPv4:

		res.Time = "0"
		res.Protocol = "ICMPv4"
		codeType := icmpv6.TypeCode.Code()
		res.Info = fmt.Sprintf("icmp-type %d", codeType)
		res.Source = eth.SrcMAC.String()
		res.Destination = eth.DstMAC.String()
		res.Length = strconv.Itoa(packet.Metadata().Length) + "bytes"

	case layers.LayerTypeICMPv6:

		res.Time = "0"
		res.Protocol = "ICMPv6"
		codeType := icmpv6.TypeCode.Code()
		res.Info = fmt.Sprintf("icmp-type %d", codeType)
		res.Source = eth.SrcMAC.String()
		res.Destination = eth.DstMAC.String()
		res.Length = strconv.Itoa(packet.Metadata().Length) + "bytes"

	case layers.LayerTypeIGMP:

		res.Time = "0"
		if igmp.Type == 0x16 || igmp.Type == 0x12 {
			res.Protocol = "IGMPv2"
		}
		if igmp.Type == 0x17 {
			res.Protocol = "Leave Group"
		}

		if igmp.Type == 0x22 {
			res.Protocol = "IGMPv3"
		}
		codeType := icmpv6.TypeCode.Code()
		res.Info = fmt.Sprintf("icmp-type %d", codeType)
		res.Source = eth.SrcMAC.String()
		res.Destination = eth.DstMAC.String()
		res.Length = strconv.Itoa(packet.Metadata().Length) + "bytes"

	}

	return &res
}

// func sendToTable() tableContent{
//  return  =<-tableShowData
// }

func firstCell(a fyne.App, dataChan chan tableContent) fyne.CanvasObject {

	// flag := binding.BindInt(&ExitFlag)

	// selectDev := widget.NewSelect(Di.GetDev(), func(s string) {
	// 	fmt.Println(s + "in firstCell")
	// 	if len(s) == 0 {
	// 		w2 := a.NewWindow("error")
	// 		w2.SetContent(widget.NewLabel("Select one device"))
	// 		w2.Resize(fyne.NewSize(100, 100))
	// 		w2.Show()

	// 	} else {
	// 		go SetDev(s)
	// 	}

	// })

	// selectDev.Resize(fyne.NewSize(100, 200))
	// selectDev.Move(fyne.NewPos(0, 0))
	// selectDev.SetSelectedIndex(0)
	// // 输入过滤规则的输入框
	// // snifferInput := widget.NewEntry()
	// s := new(widget.Entry)

	// //这个函数可以实时的检查输入框里的东西是否符合标准
	// s.Validator = util.Testvalitor
	// // 回车后，调用这个函数进行处理
	// s.OnSubmitted = func(s string) {
	// 	fmt.Println(123)
	// }
	// // snifferInput.Validate()

	// // snifferInput.Resize(fyne.NewSize(100, 200))
	// // snifferInput.Move(fyne.NewPos(0, 110))
	// // 开始按钮
	// startButton := widget.NewButton("Start", func() {

	// 	flag.Set(0)
	// 	ExitFlag = 0
	// 	startCap = 1
	// 	fmt.Println(ExitFlag)
	// 	packetCap(SelectedDev, dataChan)

	// })

	// // 结束按钮
	// finishButton := widget.NewButton("Finish", func() {

	// 	flag.Set(1)
	// 	ExitFlag = 1
	// 	fmt.Println("   stop", ExitFlag)
	// 	selectDev.Refresh()
	// 	selectDev.SetSelectedIndex(0)
	// })

	// // 保存按钮
	// saveButton := widget.NewButton("Save", func() {})

	// // 读取按钮
	// loadButton := widget.NewButton("Load", func() {})

	// // 设置布局

	// // optionContainer := container.NewAdaptiveGrid(4, startButton, finishButton, saveButton, loadButton)
	// // firstContent := container.NewAdaptiveGrid(2, selectDev, optionContainer)
	// selectContainer := container.NewGridWrap(fyne.NewSize(400, 50), selectDev)
	// inputContainer := container.NewGridWrap(fyne.NewSize(400, 50), s)
	// // cellContainer := container.New(layout.NewGridLayoutWithColumns(2), firstContent, inputContainer)

	// leftGrid := container.NewGridWithRows(2, selectContainer, inputContainer)
	// leftContainer := container.NewGridWrap(fyne.NewSize(00, 100), leftGrid)
	// // leftContainer.Move(fyne.NewPos(100, 100))
	// rightGrid := container.NewGridWrap(fyne.NewSize(80, 60), startButton, finishButton, saveButton, loadButton)
	// rightContainer := container.NewGridWrap(fyne.NewSize(400, 100), rightGrid)
	// cellContainer := container.NewAdaptiveGrid(2, leftContainer, rightContainer)

	// cellContainer.Resize(fyne.NewSize(800, 100))

	return nil
}

func secondCell(callback func(string), a fyne.App, w fyne.Window, tableRowDataStruct tableContent) fyne.CanvasObject {
	// 	// headLabel := widget.NewLabel("datashow")
	// 	// packetDis := <-util.PacketChain
	// 	// packetDis.Metadata().Timestamp.Day()

	// 	// colLen := 1

	// 	// COLLEN := binding.BindInt(&colLen)
	// 	head := [][]string{
	// 		{"No", "Time", "Source", "Destination", "Protocol", "Lenght", "Info"},
	// 	}

	// 	// head := newTableContent()
	// 	// tableShowData <- *head
	// 	// rowLen := 1
	// 	// demAtt := make([][]string, 0)
	// 	demAtt := make([][]string, 0)
	// 	var rowStringArr []string

	// 	// fmt.Println("&&&")
	// 	// tableRowDataStruct := <-tableShowData
	// 	// fmt.Printf("%v\n", tableRowDataStruct)
	// 	// rowStringArr = append(rowStringArr, tableRowDataStruct.No)
	// 	// rowStringArr = append(rowStringArr, tableRowDataStruct.Time)
	// 	// rowStringArr = append(rowStringArr, tableRowDataStruct.Source)
	// 	// rowStringArr = append(rowStringArr, tableRowDataStruct.Destination)
	// 	// rowStringArr = append(rowStringArr, tableRowDataStruct.Protocol)
	// 	// rowStringArr = append(rowStringArr, tableRowDataStruct.Length)
	// 	// rowStringArr = append(rowStringArr, tableRowDataStruct.Info)

	// 	// demAtt = append(demAtt, rowStringArr)
	// 	go func() {
	// 		// tableRowDataStruct := dataChan
	// 		fmt.Printf("%v\n", tableRowDataStruct)
	// 		rowStringArr = append(rowStringArr, tableRowDataStruct.No)
	// 		rowStringArr = append(rowStringArr, tableRowDataStruct.Time)
	// 		rowStringArr = append(rowStringArr, tableRowDataStruct.Source)
	// 		rowStringArr = append(rowStringArr, tableRowDataStruct.Destination)
	// 		rowStringArr = append(rowStringArr, tableRowDataStruct.Protocol)
	// 		rowStringArr = append(rowStringArr, tableRowDataStruct.Length)
	// 		rowStringArr = append(rowStringArr, tableRowDataStruct.Info)
	// 		demAtt = append(demAtt, rowStringArr)

	// 	}()

	// 	if startCap == 1 {

	// 	}

	// 	// fmt.Printf("%v\n", demAtt[0][1])

	// 	// fmt.Printf("%d: %d\n", len(demAtt)+1, len(demAtt[0]))
	// 	// borderTable := container.NewBorder(nil, nil, nil, nil)

	// 	tableHead := widget.NewTable(nil, nil, nil)
	// 	// tableContent := widget.NewTable(nil, nil, nil)
	// 	// tableContent.Length = func() (int, int) { return 1, 7 }]
	// 	tableHead.Length = func() (int, int) {
	// 		// cl, _ := COLLEN.Get()
	// 		return len(demAtt), 7
	// 	}

	// 	for i := 0; i < 7; i++ {
	// 		tableHead.SetColumnWidth(i, 100)
	// 		// tableContent.SetColumnWidth(1, 100)
	// 	}
	// 	tableHead.CreateCell = func() fyne.CanvasObject {
	// 		return new(canvas.Text)
	// 	}
	// 	// tableContent.CreateCell = func() fyne.CanvasObject {
	// 	// 	return new(canvas.Text)
	// 	// }

	// 	tableHead.UpdateCell = func(id widget.TableCellID, template fyne.CanvasObject) {
	// 		tbl := template.(*canvas.Text)
	// 		// fmt.Println(id.Row)
	// 		// tbl.Text = demAtt[id.Row][id.Col]
	// 		switch id.Row {
	// 		case 0:
	// 			tbl.Text = head[id.Row][id.Col]
	// 		default:
	// 			tbl.Text = demAtt[id.Row-1][id.Col]
	// 		}

	// 	}

	// 	tableHead.OnSelected = func(id widget.TableCellID) {
	// 		dialog.ShowInformation("res", strconv.Itoa(id.Col)+strconv.Itoa(id.Row), w)
	// 	}
	// 	// tableHead.Refresh()
	// 	// go func() {
	// 	// 	for i := 0; i < 3; i++ {
	// 	// 		cl, _ := COLLEN.Get()
	// 	// 		cl = cl + 1
	// 	// 		COLLEN.Set(cl)
	// 	// 	}

	// 	// }()

	// 	displayContainer := container.NewVScroll(tableHead)

	// 	// bodyContainer := container.NewVScroll(tableContent)
	// 	// wapContainer := container.NewVSplit(displayContainer, bodyContainer)
	// 	wapContainer := container.NewAdaptiveGrid(1, displayContainer)

	return nil
}
func main() {

	snifferApp := app.New()

	mainWindow := snifferApp.NewWindow("lisx-sniffer")
	var tableShowData = make(chan tableContent, 100)
	// var tableRowDataStruct = new(tableContent)

	flag := binding.BindInt(&ExitFlag)

	tableHead := widget.NewTable(nil, nil, nil)

	selectDev := widget.NewSelect(Di.GetDev(), func(s string) {
		fmt.Println(s + "in firstCell")
		if len(s) == 0 {
			w2 := snifferApp.NewWindow("error")
			w2.SetContent(widget.NewLabel("Select one device"))
			w2.Resize(fyne.NewSize(100, 100))
			w2.Show()

		} else {
			go SetDev(s)
		}

	})

	selectDev.Resize(fyne.NewSize(100, 200))
	selectDev.Move(fyne.NewPos(0, 0))
	selectDev.SetSelectedIndex(0)
	// 输入过滤规则的输入框
	// snifferInput := widget.NewEntry()
	s := new(widget.Entry)

	//这个函数可以实时的检查输入框里的东西是否符合标准
	s.Validator = util.Testvalitor
	// 回车后，调用这个函数进行处理
	s.OnSubmitted = func(s string) {
		fmt.Println(123)
	}
	// snifferInput.Validate()

	// snifferInput.Resize(fyne.NewSize(100, 200))
	// snifferInput.Move(fyne.NewPos(0, 110))
	// 开始按钮
	startButton := widget.NewButton("Start", func() {

		flag.Set(0)
		ExitFlag = 0
		startCap = 1
		fmt.Println(ExitFlag)
		go packetCap(SelectedDev, tableShowData)
		tableHead.Refresh()

	})

	// 结束按钮
	finishButton := widget.NewButton("Finish", func() {

		flag.Set(1)
		ExitFlag = 1
		fmt.Println("   stop", ExitFlag)
		selectDev.Refresh()
		selectDev.SetSelectedIndex(0)
		tableHead.CreateCell().Refresh()
	})

	// 保存按钮
	saveButton := widget.NewButton("Save", func() {})

	// 读取按钮
	loadButton := widget.NewButton("Load", func() {})

	// 设置布局

	// optionContainer := container.NewAdaptiveGrid(4, startButton, finishButton, saveButton, loadButton)
	// firstContent := container.NewAdaptiveGrid(2, selectDev, optionContainer)
	selectContainer := container.NewGridWrap(fyne.NewSize(400, 50), selectDev)
	inputContainer := container.NewGridWrap(fyne.NewSize(400, 50), s)
	// cellContainer := container.New(layout.NewGridLayoutWithColumns(2), firstContent, inputContainer)

	leftGrid := container.NewGridWithRows(2, selectContainer, inputContainer)
	leftContainer := container.NewGridWrap(fyne.NewSize(00, 100), leftGrid)
	// leftContainer.Move(fyne.NewPos(100, 100))
	rightGrid := container.NewGridWrap(fyne.NewSize(80, 60), startButton, finishButton, saveButton, loadButton)
	rightContainer := container.NewGridWrap(fyne.NewSize(400, 100), rightGrid)
	cellContainer := container.NewAdaptiveGrid(2, leftContainer, rightContainer)

	cellContainer.Resize(fyne.NewSize(800, 100))

	// box1 := firstCell(snifferApp, tableShowData)
	// fmt.Printf("box1 %v\n", box1.Size())
	// box1.Resize(fyne.NewSize(300, 1000))
	// box1.Move(fyne.NewPos(0, 500))

	// go func() {

	// }()

	head := [][]string{
		{"No", "Time", "Source", "Destination", "Protocol", "Lenght", "Info"},
	}

	// head := newTableContent()
	// tableShowData <- *head
	// rowLen := 1
	// demAtt := make([][]string, 0)

	// demAtt = append(demAtt, rowStringArr)

	if startCap == 1 {

	}

	// fmt.Printf("%v\n", demAtt[0][1])

	// fmt.Printf("%d: %d\n", len(demAtt)+1, len(demAtt[0]))
	// borderTable := container.NewBorder(nil, nil, nil, nil)

	// tableHead := widget.NewTable(nil, nil, nil)
	// tableContent := widget.NewTable(nil, nil, nil)
	// tableContent.Length = func() (int, int) { return 1, 7 }]
	tableHead.Length = func() (int, int) {
		// cl, _ := COLLEN.Get()
		return len(demAtt), 7
	}

	for i := 0; i < 7; i++ {
		tableHead.SetColumnWidth(i, 100)
		// tableContent.SetColumnWidth(1, 100)
	}
	tableHead.CreateCell = func() fyne.CanvasObject {
		return new(canvas.Text)
	}
	// tableContent.CreateCell = func() fyne.CanvasObject {
	// 	return new(canvas.Text)
	// }

	tableHead.UpdateCell = func(id widget.TableCellID, template fyne.CanvasObject) {
		tbl := template.(*canvas.Text)
		// fmt.Println(id.Row)
		// tbl.Text = demAtt[id.Row][id.Col]
		switch id.Row {
		case 0:
			tbl.Text = head[id.Row][id.Col]
		default:
			tbl.Text = demAtt[id.Row-1][id.Col]
		}

	}

	// tableHead.OnSelected = func(id widget.TableCellID) {
	// 	dialog.ShowInformation("res", strconv.Itoa(id.Col)+strconv.Itoa(id.Row))
	// }
	// tableHead.Refresh()
	// go func() {
	// 	for i := 0; i < 3; i++ {
	// 		cl, _ := COLLEN.Get()
	// 		cl = cl + 1
	// 		COLLEN.Set(cl)
	// 	}

	// }()

	displayContainer := container.NewVScroll(tableHead)

	// bodyContainer := container.NewVScroll(tableContent)
	// wapContainer := container.NewVSplit(displayContainer, bodyContainer)
	wapContainer := container.NewAdaptiveGrid(1, displayContainer)
	// box2 := secondCell(nil, snifferApp, mainWindow, test11)
	// box2 := widget.NewLabel("box2")
	box3 := widget.NewLabel("box3")
	box4 := widget.NewLabel("box4")

	mainContainer := container.New(layout.NewGridWrapLayout(fyne.NewSize(800, 150)), cellContainer, wapContainer, box3, box4)

	mainWindow.SetContent(mainContainer)

	mainWindow.Show()

	snifferApp.Run()

}
