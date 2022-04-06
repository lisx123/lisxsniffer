package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/widget"
)

func main() {

	ap := app.New()
	win := ap.NewWindow("table test")
	colLen := 1

	COLLEN := binding.BindInt(&colLen)
	data := [][]string{
		{"No", "Time", "Source", "Destination", "Protocol", "Lenght", "Info"}}
	darta2 := [][]string{
		{"1", "111.111", "11111111111", "222222222", "222", "233323", "123dyhqiw rwgjf8q79ewrt yhq34oy6viov6uty"},
		{"1", "111.111", "11111111111", "222222222", "222", "233323", "123dyhqiw rwgjf8q79ewrt yhq34oy6viov6uty"},
		{"1", "111.111", "11111111111", "222222222", "222", "233323", "123dyhqiw rwgjf8q79ewrt yhq34oy6viov6uty"},
		{"1", "111.111", "11111111111", "222222222", "222", "233323", "123dyhqiw rwgjf8q79ewrt yhq34oy6viov6uty"},
	}

	// borderTable := container.NewBorder(nil, nil, nil, nil)

	tableHead := widget.NewTable(nil, nil, nil)

	tableHead.Length = func() (int, int) {
		cl, _ := COLLEN.Get()
		return cl + 1, 7
	}

	for i := 0; i < 7; i++ {
		tableHead.SetColumnWidth(i, 100)

	}
	tableHead.CreateCell = func() fyne.CanvasObject {
		return new(canvas.Text)
	}

	tableHead.UpdateCell = func(id widget.TableCellID, template fyne.CanvasObject) {
		tbl := template.(*canvas.Text)
		// COLLEN.AddListener(binding.NewDataListener(func() {
		// 	update, _ := COLLEN.Get()
		// 	update += 1
		// 	COLLEN.Set(update)
		// }))

		// tableHead.Length = func() (int, int) {
		// 	return cl, 7
		// }
		// tableHead.Refresh()
		// cl, _ := COLLEN.Get()
		// cl = cl + 1
		// COLLEN.Set(cl)
		switch id.Row {
		case 0:
			tbl.Text = data[id.Row][id.Col]
		default:
			tbl.Text = darta2[id.Row-1][id.Col]
		}

	}
	go func() {
		for i := 0; i < 3; i++ {
			cl, _ := COLLEN.Get()
			cl = cl + 1
			COLLEN.Set(cl)
		}

	}()

	// tableHead.OnSelected = func(id widget.TableCellID) {
	// 	dialog.ShowInformation("res", strconv.Itoa(id.Col)+strconv.Itoa(id.Row), win)
	// }

	// displayContainer := container.NewVScroll(tableHead)

	// // bodyContainer := container.NewVScroll(tableContent)
	// // wapContainer := container.NewVSplit(displayContainer, bodyContainer)
	// wapContainer := container.NewAdaptiveGrid(1, displayContainer)
	dis := container.NewVScroll(tableHead)
	win.SetContent(dis)
	win.Resize(fyne.Size{1000, 1000})
	win.Show()
	ap.Run()
}
