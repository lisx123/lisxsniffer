package util

import (
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"
)

func CreateTree() fyne.CanvasObject {
	treedata := make(map[string][]string, 0)
	treedata[""] = []string{"dataframe"}

	t := widget.NewTree(nil, nil, nil, nil)
	// t := widget.NewTreeWithStrings(treedata)

	t.ChildUIDs = func(uid string) (c []string) {
		c = treedata[uid]
		return
	}

	t.IsBranch = func(uid string) (b bool) {
		_, b = treedata[uid]
		return
	}
	t.CreateNode = func(branch bool) fyne.CanvasObject {
		return widget.NewLabel("Template Object")
	}
	t.UpdateNode = func(uid string, branch bool, node fyne.CanvasObject) {
		lbl := node.(*widget.Label)
		lbl.Wrapping = fyne.TextWrapOff
		lbl.Alignment = fyne.TextAlignLeading
		lbl.SetText(uid)
	}
	// if Onclicked {
	go func() {

		for {

			// if Restart {
			// 	treedata[""] = []string{"dataframe"}
			// 	t.Refresh()
			// 	break
			// }

			if len(TreeDataSwapChan) == 0 {
				time.Sleep(1 * time.Second)
			} else {

				tt := <-TreeDataSwapChan

				treedata = tt.TreeIten
				t.Refresh()
				// fmt.Println("in loop tree routine", treedata)

			}
		}

	}()

	// }

	return t
}
