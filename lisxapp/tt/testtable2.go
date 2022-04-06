package main

// 有一个bug修复之后的
import (
	"fmt"
	"strconv"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

func NewTableT() fyne.CanvasObject {

	tableData := make([][]string, 0)
	table := widget.NewTable(func() (int, int) { return len(tableData), 3 },
		func() fyne.CanvasObject {
			item := widget.NewLabel("template")
			return item
		},

		func(i widget.TableCellID, o fyne.CanvasObject) {
			fmt.
				Println("ROW :: ", i.Row, " COL:: ", i.Col)
			o.(*widget.Label).SetText(tableData[i.Row][i.Col])
		})
	table.SetColumnWidth(0, 40)
	table.SetColumnWidth(1, 80)
	table.SetColumnWidth(2, 80)

	go func() {
		// time.Sleep(3 * time.Second)i := 0; i < 10; i++
		for {
			time.Sleep(1 * time.Second)
			tableData = append(tableData, []string{strconv.Itoa(len(tableData) + 1), "test1", "test2"})
			table.Refresh()

		}

		table.ScrollToBottom()

	}()

	c := container.New(layout.NewMaxLayout(), table)

	return c
}
func main() {
	a := app.New()
	w := a.NewWindow("Some title")

	c := NewTableT()
	w.SetContent(c)
	w.Resize(fyne.NewSize(300, 200))
	w.ShowAndRun()
}
