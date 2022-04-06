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

		// fmt.Printf("%p\n", &SwapChan)

		// 对数据进行初始化设置
		ctx, cancelF = InitVerb()

		go packetCap(SelectedDev, ctx, a)

		startButton.Disable()
		stopButton.Enable()

		// tbl.Refresh()

	}

	stopButton.OnTapped = func() {

		// close(tableCellsList)
		IsStoped = true

		selectDev.Refresh()
		selectDev.SetSelectedIndex(0)
		// OnFinish()
		cancelF()

		stopButton.Disable()
		startButton.Enable()
		// tbl.Refresh()

	}

	// 设置布局

	selectContainer := container.NewMax(selectDev)
	inputContainer := container.NewMax(inputFilter)

	leftGrid := container.NewVBox(selectContainer, inputContainer)
	leftContainer := container.NewMax(leftGrid)
	rightGrid := container.NewGridWrap(fyne.NewSize(80, 60), startButton, stopButton)
	cellContainer := container.NewAdaptiveGrid(2, leftContainer, rightGrid)

	return cellContainer
}
