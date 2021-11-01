package main

import (
	esnapi "esn-api-golang/esn-api"
	"fmt"
	"sync"
)

type listener struct{}

func (l listener) NotificationReceived(ntf esnapi.PackRespNotification) {
	fmt.Println(ntf.Content)
}
func (l listener) SessionLogout(err esnapi.PackResult) {
	fmt.Println(err.Error)
}

func main() {
	esnapi.DebugMode = true
	session, err := esnapi.MakeESNSession("39.100.5.139:3003", "root", "turtle", 5000)
	if err != nil {
		panic(err)
	}
	session.SetListener(new(listener))

	// session.RequestNotification(0, 100)
	err = session.PushNotification("root,rockchin", "TestMessage", "TheFirstNotificationSendByGolangAPI 哈哈哈哈")
	if err != nil {
		panic(err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	wg.Wait()
}
