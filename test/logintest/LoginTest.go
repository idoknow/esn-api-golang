package main

import (
	esnapi "esn-api-golang/esn-api"
	"fmt"
	"sync"
)

func main() {
	session, err := esnapi.MakeESNSession("39.100.5.139:3003", "rock", "000112rock.,.", 5000)
	if err != nil {
		panic(err)
	}
	session.SetListener(func(ntf esnapi.PackRespNotification) {
		fmt.Println(ntf.Content)
	}, func(err esnapi.PackResult) {
		fmt.Println(err.Error)
	})

	// session.RequestNotification(0, 100)
	err = session.PushNotification("root,rockchin", "TestMessage", "TheFirstNotificationSendByGolangAPI 哈哈哈哈")
	if err != nil {
		panic(err)
	}

	err = session.RemoveAccount("rock", true)
	if err != nil {
		panic(err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	wg.Wait()
}
