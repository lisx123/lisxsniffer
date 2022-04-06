package util

import (
	"context"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type RowData struct {
	No          string
	Time        string
	Source      string
	Destination string
	Protocol    string
	Length      string
	Info        string
}

type DevInfo struct {
	MapInfo map[string]string
}

type TreeDataStruct struct {
	PacketIndex int
	TreeIten    map[string][]string //treeItem
	Data        []byte
}

var Di = *NewDevInfo()
var SelectedDev string

var PacketIndex = 0 //表示每一个包的序列号

var Rowdatas [][]string
var ErrChan chan error
var PacketDataCols = [7]string{"No", "Time", "Source", "Destination", "Protocol", "Length", "Info"}
var FilterRuls = []string{"arp", "tcp", "udp", "icmp", "igmp",
	"ip", "ip6"}
var FilterRulsAdv = []string{"port", "and"}

// 用于保存index-packet对
var PacketMap map[int]gopacket.Packet
var Filter string
var RightFilter bool
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

var SwapChan chan RowData

var TreeDataSwapChan = make(chan TreeDataStruct, 1)

var PacketDataShowChan = make(chan []byte, 1)
var IsStoped bool = false
var Onclicked bool = false
var Restart bool = false
var StartCount int = 0
var Ctx context.Context
var CancelF context.CancelFunc

func InitVerb() (context.Context, context.CancelFunc) {

	Ctx, CancelF = context.WithCancel(context.Background())
	tmpchan := make(chan RowData, 100)
	SwapChan = tmpchan
	Onclicked = false
	PacketIndex = 0
	PacketMap = make(map[int]gopacket.Packet, 100)
	Rowdatas = [][]string{}

	return Ctx, CancelF
}
