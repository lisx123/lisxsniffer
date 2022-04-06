package util

import (
	"encoding/hex"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"
)

func CreateLabel() fyne.CanvasObject {
	txt := "packet data"
	lbl := widget.Label{}
	// lbl.Text = txt
	lbl.SetText(txt)
	lbl.Wrapping = fyne.TextWrapBreak
	// lbl.TextStyle = fyne.TextStyle{}
	go func() {
		lbl.SetText(txt)
		lbl.Refresh()
		for {
			// if Restart { //IsStoped
			// 	txt = "packet data"
			// 	lbl.SetText(txt)
			// 	lbl.Refresh()
			// 	// break
			// }

			if len(PacketDataShowChan) == 0 {
				time.Sleep(1 * time.Second)
				// continue
			} else {
				bt := <-PacketDataShowChan
				// hex := fmt.Sprintf("%x", bt)
				txt = hex.Dump(bt)
				lbl.SetText(txt)
				lbl.Refresh()
			}

			// break

		}
		// return

	}()

	return &lbl
}
