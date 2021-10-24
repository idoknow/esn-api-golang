package esnapi

import (
	"time"
)

func (session *ESNSession) AliveLoop() {
	tiker := time.NewTicker(30 * time.Second)
	for {
		<-tiker.C
		DebugMsg("AliveLoop", "Checking")
		go session.check()
	}
}
func (session *ESNSession) check() {
	token := randToken()
	var pack PackTest
	pack.Token = token
	pack.Msg = "TestFromGolangAPI"
	pack.Integer = 1
	WritePackage(*session.Conn, pack, 0, "")
}
