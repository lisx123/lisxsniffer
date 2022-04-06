package main

import (
	"fmt"
	"time"
)

func main() {

	t := time.Now()
	t1 := t.Local().Unix()
	fmt.Println("时间戳", t1)
	// fmt.Println(reflect.TypeOf(filename1))
	// filename := strconv.Itoa(int(filename1))
	b := t.Local().Format("2006-01-02 15:04:05")
	fmt.Println(b)

}
