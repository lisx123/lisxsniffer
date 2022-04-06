package main

import (
	"fmt"

	"github.com/google/gopacket/pcap"
)

// import (
// 	"fmt"
// 	"strconv"
// )

// func main() {
// 	str := "52"
// 	port1, err := strconv.ParseInt(str, 0, 0)
// 	if err != nil {
// 		fmt.Println("error", err)
// 	}

// 	fmt.Printf("port :%d\n", port1)
// }

// func main() {
// 	// 编码
// 	src := []byte("hello")
// 	maxEnLen := hex.EncodedLen(len(src)) // 最大编码长度
// 	dst1 := make([]byte, maxEnLen)
// 	n := hex.Encode(dst1, src)
// 	dst2 := hex.EncodeToString(src)
// 	fmt.Println("编码后的结果:", string(dst1[:n]))
// 	fmt.Println("编码后的结果:", dst2)
// 	// 解码
// 	src = dst1
// 	maxDeLen := hex.DecodedLen(len(src))
// 	dst1 = make([]byte, maxDeLen)
// 	n, err := hex.Decode(dst1, src)
// 	if err != nil {
// 		log.Println(err)
// 	} else {
// 		fmt.Printf("%s解码后的数据为:%s\n", src, string(dst1[:n]))
// 	}
// 	dst3, err := hex.DecodeString(string(src))
// 	fmt.Printf("%s解码后的数据为:%s\n", src, string(dst3[:n]))
// 	// dump
// 	fmt.Printf(hex.Dump(src))
// 	// dumper
// 	stdoutDumper := hex.Dumper(os.Stdout)
// 	defer stdoutDumper.Close()

// 	stdoutDumper.Write(src)
// }

func main() {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Println(err)
	}
	for _, d := range devs {
		fmt.Printf("%v\n", d)
	}
}
