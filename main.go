package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/sachin-puranik/verizy-go-fingerprint/fingerprint"
)

const constvid = 0x1A86
const constpid = 0x7523

func main() {
	scanner := fingerprint.NewUSB(constvid, constpid, 0x0000)
	//c := &serial.Config{Name: "/dev/tty.usbserial-1420", Baud: 9600 * 6, ReadTimeout: time.Millisecond * 500}
	//scanner := fingerprint.NewSerial(c, 0x0000)
	err := scanner.Capture()
	if err != nil {
		log.Fatal("Wow...Cant't handel err =>", err.Error())
	}
	defer scanner.Release()

	if scanner.VerifyPassword() == true {
		log.Println("Password verified")
	}

	if sp, err := scanner.GetSystemParameters(); err == nil {
		b, _ := json.Marshal(sp)
		fmt.Println(string(b))
	}

}
