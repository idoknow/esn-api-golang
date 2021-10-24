package esnapi

import "fmt"

var DebugMode = false

func DebugMsg(sub string, msg string) {
	if DebugMode {
		fmt.Println("[Debug-"+sub+"]", msg)
	}
}
