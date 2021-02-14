package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/SachinPuranik/verizy-go-fingerprint/fingerprint"
	"github.com/tarm/serial"
	//"github.com/tarm/serial"
)

const constvid = 0x1A86
const constpid = 0x7523

func main() {
	var breakMe bool
	var choice int
	//scanner := fingerprint.NewUSB(constvid, constpid, 0x0000)
	c := &serial.Config{Name: "/dev/tty.usbserial-1420", Baud: 9600 * 6, ReadTimeout: time.Millisecond * 500}
	scanner := fingerprint.NewSerial(c, 0x0000)
	err := scanner.Capture()
	if err != nil {
		log.Fatal("Wow...Cant't handel err =>", err.Error())
	}
	defer scanner.Release()

	for breakMe == false {
		fmt.Println("Choose your option:")
		fmt.Println("1 - Verify Password")
		fmt.Println("2 - System Params")
		fmt.Println("3 - Search")
		fmt.Println("4 - Enroll")
		fmt.Println("5 - Clear Database")
		fmt.Println("9 - Exit")
		//choice = 4
		switch fmt.Scan(&choice); choice {
		//switch choice {
		case 1:
			if scanner.VerifyPassword() == true {
				log.Println("Password verified")
			} else {
				log.Println("Password wrong")
			}

		case 2:
			if sp, err := scanner.GetSystemParameters(); err == nil {
				b, _ := json.Marshal(sp)
				fmt.Println(string(b))
			}
		case 3:
			//Place holder for Enroll Function
			Search(scanner)
		case 4:
			Enroll(scanner)
		case 5:
			err := scanner.ClearDatabase()
			if err != nil {
				log.Printf(err.Error())
			} else {
				log.Printf("database cleared now")
			}
		case 9:
			breakMe = true
			fmt.Println("Stoping the program - with Exit Option")
		default:
			fmt.Println("Thats Invalid choice")
		}

	}

}

//Search -
func Search(scanner fingerprint.ScannerIO) {
	log.Println("R307 : Waiting for finger...")

	for scanner.ReadImage() == false {
		log.Println("R307 : Still waiting for finger...")
	}

	scanner.ConvertImage(fingerprint.FINGERPRINT_CHARBUFFER1)
	result, err := scanner.SearchTemplate(fingerprint.FINGERPRINT_CHARBUFFER1, 0, -1)
	if err == nil {
		log.Printf("PositionNumber : %d, AccuracyScore: %d\n", result.PositionNumber, result.AccuracyScore)
	} else {
		log.Printf(err.Error())
	}

}

//Enroll -
func Enroll(scanner fingerprint.ScannerIO) {
	log.Println("R307 : Waiting for finger...")

	for scanner.ReadImage() == false {
		log.Println("R307 : Still waiting for finger...")
	}

	scanner.ConvertImage(fingerprint.FINGERPRINT_CHARBUFFER1)
	result, _ := scanner.SearchTemplate(fingerprint.FINGERPRINT_CHARBUFFER1, 0, -1)

	if result.PositionNumber >= 0 {
		log.Println("Template already exists at position #", result.PositionNumber)
		return
	}
	log.Println("Remove and keep the finger again")
	time.Sleep(2 * time.Second)

	for scanner.ReadImage() == false {
		log.Println("R307 : Still waiting for finger...")
	}
	scanner.ConvertImage(fingerprint.FINGERPRINT_CHARBUFFER2)

	accuracyScore, err := scanner.CompareCharacteristics()
	if accuracyScore == 0 {
		log.Printf("Fingers do not match")
		return
	}

	err = scanner.CreateTemplate()
	newPosition := -1
	newPosition, err = scanner.StoreTemplate(newPosition, fingerprint.FINGERPRINT_CHARBUFFER1)
	if err != nil {
		log.Printf("Unable to store template")
		return
	}

	log.Println("finger enrolled successfully. New template position #", newPosition)

}
