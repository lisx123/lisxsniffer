package main

import (
	"fmt"
	"sync"
	"time"
)

func main() {
	ch := make(chan string, 1)
	var wg sync.WaitGroup
	wg.Add(2)
	go sendData(ch, wg)
	go getData(ch, wg)
	wg.Wait()
	time.Sleep(1e9)

}

func sendData(ch chan string, wg sync.WaitGroup) {

	ch <- "golang"
	wg.Done()
}

func getData(ch chan string, wg sync.WaitGroup) {
	for {
		if len(ch) == 0 {

			continue
		}
		fmt.Println("len =:", len(ch))
		fmt.Println(<-ch)
		fmt.Println("len =:", len(ch))

	}

}
