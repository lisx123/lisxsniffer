package util

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

func FirstCell(a fyne.App, win fyne.Window) fyne.CanvasObject {
	selectDev := widget.NewSelect(Di.GetDev(), func(s string) {
		fmt.Println(s + "in firstCell")
		if len(s) == 0 {
			w2 := a.NewWindow("error")
			w2.SetContent(widget.NewLabel("Select one device"))
			w2.Resize(fyne.NewSize(100, 100))
			w2.Show()

		} else {
			go SetDev(s)
		}

	})

	selectDev.SetSelectedIndex(0)

	// 输入过滤规则的输入框
	// snifferInput := widget.NewEntry()
	inputFilter := new(widget.Entry)
	// inputFilter.Wrapping=fyne.TextWrap()
	//这个函数可以实时的检查输入框里的东西是否符合标准
	inputFilter.Validator = Textvalitor
	inputFilter.Validate()
	Filter = inputFilter.Text
	// 回车后，调用这个函数进行处理

	inputFilter.OnSubmitted = func(s string) {
		filter := strings.ToLower(s)
		// 将输入的字符串进行切割，以" "空格为分割条件
		strs := strings.SplitN(filter, " ", -1)
		if len(strs) == 0 {
			RightFilter = true
		}
		if len(strs) == 1 {
			if isInStringArray(strs[0], FilterRuls) {
				RightFilter = true
			} else {
				RightFilter = false
			}
		} else {
			if isInStringArray("and", strs) {
				_, err := strconv.ParseInt(strs[len(strs)-1], 0, 0)
				if err != nil {
					RightFilter = false
				}
				RightFilter = true
			}
		}
		if !RightFilter {
			msg := fmt.Sprintf("filter error:%s ont support", filter)
			err := errors.New(msg)
			dialog.ShowError(err, win)
			inputFilter.SetText("")
			inputFilter.Refresh()
			return
		}
		Filter = filter
		fmt.Println(" filter", Filter)
	}

	// 开始按钮
	startButton := &widget.Button{Text: "Start"}
	stopButton := &widget.Button{Text: "Stop"}
	stopButton.Disabled()
	var cancelF context.CancelFunc
	var ctx context.Context
	startButton.OnTapped = func() {
		StartCount++
		// startCap = 1
		IsStoped = false
		if StartCount == 1 {
			Restart = false
		} else {
			Restart = true
		}
		// fmt.Printf("%p\n", &SwapChan)

		// 对数据进行初始化设置
		ctx, cancelF = InitVerb()
		// InitVerb()
		//开启两个协程，一个用于抓去报文并解析，另一个将解析后的数据发送个tabkle
		// 不能重新使用是不是因为，使用的是同一个chan，即使重新赋值后，其指针也是不变的，所以不能够重新初始化，被阻塞在一起
		go packetCap(SelectedDev, ctx, a)

		startButton.Disable()
		stopButton.Enable()
		// Restart = true
		// Restart++
		// tbl.Refresh()

	}

	stopButton.OnTapped = func() {

		// close(tableCellsList)
		IsStoped = true
		Restart = false
		selectDev.Refresh()
		selectDev.SetSelectedIndex(0)
		// OnFinish()
		cancelF()

		stopButton.Disable()
		startButton.Enable()
		// tbl.Refresh()

	}

	// 设置布局

	// optionContainer := container.NewAdaptiveGrid(4, startButton, finishButton, saveButton, loadButton)
	// firstContent := container.NewAdaptiveGrid(2, selectDev, optionContainer)
	selectContainer := container.NewMax(selectDev)
	inputContainer := container.NewMax(inputFilter)
	// cellContainer := container.New(layout.NewGridLayoutWithColumns(2), firstContent, inputContainer)

	leftGrid := container.NewVBox(selectContainer, inputContainer)
	leftContainer := container.NewMax(leftGrid)
	// leftContainer.Move(fyne.NewPos(100, 100))
	rightGrid := container.NewGridWrap(fyne.NewSize(80, 60), startButton, stopButton)
	// rightContainer := container.NewGridWrap(fyne.NewSize(400, 100), rightGrid)
	cellContainer := container.NewAdaptiveGrid(2, leftContainer, rightGrid)

	return cellContainer
}
