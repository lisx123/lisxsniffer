package main

import (
	"lisxapp/util"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
)

// 对选择的设备进行抓取

var hasStoped string = "not"

func main() {

	snifferApp := app.New()

	mainWindow := snifferApp.NewWindow("lisx-sniffer")
	mainWindow.SetMaster()
	// var swapchan chan util.RowData
	// var tableRowDataStruct = new(tableContent)
	// 这里使用context控制两个线程，抓取保温线程，和向table发送数据线程

	// ctx, cancel := context.WithCancel(context.Background())
	tbl := util.DataTable(mainWindow)
	// tbl.UpdateCell = func(id widget.TableCellID, template fyne.CanvasObject) {
	// 	template.(*widget.Label).SetText("")
	// }
	firstCell := util.FirstCell(snifferApp, mainWindow)
	tbl.Refresh()

	// tbl.Refresh()
	// snifferInput.Validate()

	// snifferInput.Resize(fyne.NewSize(100, 200))
	// snifferInput.Move(fyne.NewPos(0, 110))
	firstContainer := container.NewGridWrap(fyne.NewSize(1000, 100), firstCell)
	firstContainer.Move(fyne.NewPos(0, 0))
	tblContainer := container.NewGridWrap(fyne.NewSize(1000, 200), tbl)
	tblContainer.Move(fyne.NewPos(0, 150))
	box3 := util.CreateTree()
	treeContainer := container.NewGridWrap(fyne.NewSize(1100, 200), box3)
	treeContainer.Move(fyne.NewPos(0, 360))

	box4 := util.CreateLabel()
	packerDataContainer := container.NewGridWrap(fyne.NewSize(1000, 200), box4)
	packerDataContainer.Move(fyne.NewPos(0, 540))

	mainContainer := container.NewWithoutLayout(firstContainer, tblContainer, treeContainer, packerDataContainer)

	mainWindow.SetContent(mainContainer)
	mainWindow.Resize(fyne.NewSize(1100, 1050))

	mainWindow.ShowAndRun()

	// go func() {
	// 	time.Sleep(30 * time.Second)
	// 	snifferApp.Quit()
	// }()

	// snifferApp.Run()

}
