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
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)



var tableCellsList chan []string

// 对选择的设备进行抓取


// 初始化设备列表





func main() {

	snifferApp := app.New()

	mainWindow := snifferApp.NewWindow("lisx-sniffer")
	// var tableShowData = make(chan tableContent, 100)
	// var tableRowDataStruct = new(tableContent)

	flag := binding.BindInt(&ExitFlag)
	demAtt := make([][]string, 0)
	head := [][]string{
		{"No", "Time", "Source", "Destination", "Protocol", "Lenght", "Info"},
	}

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

	// selectDev.Resize(fyne.NewSize(100, 200))
	// selectDev.Move(fyne.NewPos(0, 0))
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
		fmt.Println("start hasStoped: ", hasStoped)
		tableCellsList = make(chan []string, 100)

		// startCap = 1
		fmt.Println(ExitFlag)
		go packetCap(SelectedDev)
		// tableHead.Refresh()

	})

	// 结束按钮
	finishButton := widget.NewButton("Finish", func() {

		flag.Set(1)
		ExitFlag = 1
		fmt.Println("stop hasStoped: ", hasStoped)
		// close(tableCellsList)
		selectDev.Refresh()
		selectDev.SetSelectedIndex(0)
		demAtt = [][]string{}
		demAtt = append(demAtt, head[0])

		tableHead.Refresh()
	})

	// 保存按钮
	saveButton := widget.NewButton("Save", func() {})

	// 读取按钮
	loadButton := widget.NewButton("Load", func() {})

	// 设置布局
	fmt.Println(hasStoped)
	// optionContainer := container.NewAdaptiveGrid(4, startButton, finishButton, saveButton, loadButton)
	// firstContent := container.NewAdaptiveGrid(2, selectDev, optionContainer)
	selectContainer := container.NewMax(selectDev)
	inputContainer := container.NewMax(s)
	// cellContainer := container.New(layout.NewGridLayoutWithColumns(2), firstContent, inputContainer)

	leftGrid := container.NewVBox(selectContainer, inputContainer)
	leftContainer := container.NewMax(leftGrid)
	// leftContainer.Move(fyne.NewPos(100, 100))
	rightGrid := container.NewGridWrap(fyne.NewSize(80, 60), startButton, finishButton, saveButton, loadButton)
	// rightContainer := container.NewGridWrap(fyne.NewSize(400, 100), rightGrid)
	cellContainer := container.New(layout.NewAdaptiveGridLayout(2), leftContainer, rightGrid)

	rowIndex := 0

	tableHead.Length = func() (int, int) {
		return len(demAtt), 7
	}

	for i := 0; i < 7; i++ {

		if i == 2 || i == 3 {
			tableHead.SetColumnWidth(i, 150)
		} else {
			tableHead.SetColumnWidth(i, 80)
		}
		// tableContent.SetColumnWidth(1, 100)
	}
	tableHead.CreateCell = func() fyne.CanvasObject {
		return widget.NewLabel("head table")
	}
	// tableContent.CreateCell = func() fyne.CanvasObject {
	// 	return new(canvas.Text)
	// }
	demAtt = append(demAtt, head[0])
	fmt.Println(demAtt)

	tableHead.UpdateCell = func(id widget.TableCellID, template fyne.CanvasObject) {
		tbl := template.(*widget.Label)

		tbl.SetText(demAtt[id.Row][id.Col])

	}
	go func() {
		time.Sleep(2 * time.Second)
		for rowString := range tableCellsList {
			demAtt = append(demAtt, rowString)
		}
		// rowString := <-tableCellsList

		tableHead.ScrollToTop()
	}()
	fmt.Println(rowIndex)
	rowIndex++

	displayContainer := container.NewScroll(tableHead)

	box3 := widget.NewLabel("box3")
	box4 := widget.NewLabel("box4")

	mainContainer := container.New(layout.NewGridWrapLayout(fyne.NewSize(800, 150)), cellContainer, displayContainer, box3, box4)

	mainWindow.SetContent(mainContainer)

	mainWindow.Show()

	snifferApp.Run()

}
