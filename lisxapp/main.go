package main

import (
	"lisxapp/util"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
)

func main() {

	snifferApp := app.New()

	mainWindow := snifferApp.NewWindow("lisx-sniffer")
	mainWindow.SetMaster()

	tbl := util.DataTable(mainWindow)

	firstCell := util.FirstCell(snifferApp, mainWindow)
	tbl.Refresh()

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

}
