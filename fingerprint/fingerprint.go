package fingerprint

import (
	"bytes"
	"errors"
	"fmt"
	"log"

	"github.com/google/gousb"
	"github.com/lunixbochs/struc"
	"github.com/tarm/serial"
)

type myUSB struct {
	usbCtxt   *gousb.Context
	usbDevice *gousb.Device
	usbConfig *gousb.Config
	usbIntf   *gousb.Interface
	epIn      *gousb.InEndpoint
	epOut     *gousb.OutEndpoint

	vid gousb.ID
	pid gousb.ID
}

type mySerial struct {
	serialPort *serial.Port
	serialCfg  *serial.Config
}

//scanner - Scanner struct to hold various data members
type scanner struct {
	myUSB
	mySerial
	useSerial bool
	password  uint
}

//ScannerIO - Interface for Scanner
type ScannerIO interface {
	Capture() error
	Release()
	VerifyPassword() bool
	GetSystemParameters() (*SystemParameters, error)
	ReadImage() bool
}

// func getDefaultSerialCfg() *serial.Config {
// 	return &serial.Config{Name: "/dev/tty.usbserial-1420", Baud: 9600 * 6, ReadTimeout: time.Millisecond * 500}
// }

//NewSerial - Create scanner with serial connection
func NewSerial(serialCfg *serial.Config, password uint) ScannerIO {
	if serialCfg == nil {
		log.Fatal("Unable to open serial port due to invalid params")
	}

	s := &scanner{}
	s.serialCfg = serialCfg
	s.useSerial = true
	s.password = password
	return s
}

//NewUSB - Create scanner with usb connection
func NewUSB(vid uint16, pid uint16, password uint) ScannerIO {
	s := &scanner{}
	// Open any device with a given VID/PID using a convenience function.
	s.vid = gousb.ID(vid)
	s.pid = gousb.ID(pid)
	s.useSerial = false
	s.password = password
	return s
}

func (s *scanner) captureSerial() error {
	var err error
	s.serialPort, err = serial.OpenPort(s.serialCfg)
	if err != nil {
		log.Printf(err.Error())
		return err
	}
	return nil
}

func (s *scanner) captureUSB() error {
	var err error
	s.usbCtxt = gousb.NewContext()
	s.usbDevice, err = s.usbCtxt.OpenDeviceWithVIDPID(s.vid, s.pid)
	if err != nil {
		s.usbCtxt.Close()
		log.Printf("Could not open a device: %v\n", err)
		return err
	}

	// Switch the configuration to #1.
	s.usbConfig, err = s.usbDevice.Config(1)
	if err != nil {
		log.Printf("%s.Config(2): %v", s.usbDevice, err)
		s.usbDevice.Close()
		s.usbCtxt.Close()
		return err
	}
	// In the config #2, claim interface #3 with alt setting #0.
	s.usbIntf, err = s.usbConfig.Interface(0, 0)
	if err != nil {
		log.Fatalf("%s.Interface(0, 0): %v", s.usbConfig, err)
		s.usbConfig.Close()
		s.usbDevice.Close()
		s.usbCtxt.Close()
		return err
	}

	s.epIn, err = s.usbIntf.InEndpoint(2)
	if err != nil {
		log.Fatalf("%s.InEndpoint(2): %v", s.usbIntf, err)
		s.usbIntf.Close()
		s.usbConfig.Close()
		s.usbDevice.Close()
		s.usbCtxt.Close()
		return err
	}

	// And in the same interface open endpoint #5 for writing.
	s.epOut, err = s.usbIntf.OutEndpoint(2)
	if err != nil {
		log.Fatalf("%s.InEndpoint(2): %v", s.usbIntf, err)
		s.usbIntf.Close()
		s.usbConfig.Close()
		s.usbDevice.Close()
		s.usbCtxt.Close()
		return nil
	}

	return nil
}

func (s *scanner) Capture() (err error) {

	if s.useSerial == true {
		err = s.captureSerial()
	} else {
		err = s.captureUSB()
	}
	return err
}

func (s *scanner) releaseSerial() {

}

func (s *scanner) releaseUSB() {

	s.usbIntf.Close()
	s.usbConfig.Close()
	s.usbDevice.Close()
	s.usbCtxt.Close()
}

func (s *scanner) Release() {
	if s.useSerial == true {
		s.releaseSerial()
	} else {
		s.releaseUSB()
	}
}

func (s *scanner) writeSerial(payLoad []byte) (int, error) {
	numBytes, err := s.serialPort.Write(payLoad)
	if numBytes == 0 {
		log.Printf("%d.Write(): only %d bytes written, returned error is %v\n", s.serialPort, numBytes, err)
		return -1, err
	}
	return numBytes, err
}

func (s *scanner) writeUSB(payLoad []byte) (int, error) {
	// Write data to the USB device.
	numBytes, err := s.epOut.Write(payLoad)
	if numBytes == 0 {
		log.Printf("%s.Write([2]): only %d bytes written, returned error is %v\n", s.epOut, numBytes, err)
		numBytes = -1
	}
	return numBytes, err
}

func (s *scanner) writePacket(packetType int, payLoad []byte) (numBytes int, err error) {
	packet := buildCommandPacket(packetType, payLoad)
	if s.useSerial == true {
		numBytes, err = s.writeSerial(packet)
	} else {
		numBytes, err = s.writeUSB(packet)
	}
	return numBytes, err
}

func (s *scanner) readFragementOnSerial(readSize int) ([]byte, int, error) {

	buf := make([]byte, readSize)
	readBytes, err := s.serialPort.Read(buf)
	if err != nil {
		log.Printf("Error reading Serial Port =>%s\n", err.Error())
		readBytes = -1
	}
	return buf, readBytes, err
}

func (s *scanner) readFragementOnUSB(readSize int) ([]byte, int, error) {
	buf := make([]byte, readSize)
	readBytes, err := s.epIn.Read(buf)
	if err != nil {
		fmt.Println("Read returned an error:", err)
	} else if readBytes == 0 {
		log.Fatalf("InEndpoint(2) returned 0 bytes of data.")
	}
	return buf, readBytes, err
}

func (s *scanner) readPacket() (*ThumbPacket, error) {
	var maxReadSize, readBytes int
	var frag, buf []byte
	var err error
	var tp *ThumbPacket

	maxReadSize = 1024
	continueRead := true

	for continueRead == true {

		if s.useSerial == true {
			frag, readBytes, err = s.readFragementOnSerial(maxReadSize)
		} else {
			frag, readBytes, err = s.readFragementOnUSB(maxReadSize)
		}
		// if buf == nil {
		// 	buf = frag
		// } else {
		buf = append(buf, frag[:readBytes]...)
		// }

		if len(buf) < SMALLEST_RESPONSE_PACKET_SIZE {
			continue
		}

		if tp, err = decodeResponsePacket(buf); err != nil {
			//Handle error
		}
		if uint(len(buf)) < tp.PacketLength+9 {
			//Data receiving is still pending
			continue
		}
		continueRead = false
	}
	err = verifyChecksum(tp)
	return tp, err
}

func anyCommonErrors(tp *ThumbPacket) (bool, error) {
	var err error
	var op bool

	op = true
	err = nil

	if tp.PacketType != FINGERPRINT_ACKPACKET {
		err = errors.New("the received packet is no ack packet")
	}

	receivedPacketPayload := []byte(tp.PayLoad)

	if receivedPacketPayload[0] == FINGERPRINT_OK && err == nil {
		op = false
	} else if receivedPacketPayload[0] == FINGERPRINT_ERROR_COMMUNICATION {
		err = errors.New("Communication error")
	} else if receivedPacketPayload[0] == FINGERPRINT_ERROR_INVALIDREGISTER {
		err = errors.New("Invalid register number")
	} else {
		err = errors.New("Unknownon error occured")
	}

	return op, err
}

func (s *scanner) VerifyPassword() bool {
	var ret bool
	ret = true
	payLoad := getPayloadForVerifyPassword(s.password)
	_, errWrite := s.writePacket(FINGERPRINT_COMMANDPACKET, payLoad)
	if errWrite != nil {
		ret = false
	}
	tp, errRead := s.readPacket()
	if errRead != nil {
		//Handle packet read error
	}
	if b, err := anyCommonErrors(tp); b == true {
		log.Printf(err.Error())
		ret = b
	}
	return ret
}

func (s *scanner) SetPassword(password uint) bool {
	var ret bool
	ret = true

	s.password = password

	payLoad := getPayloadForSetPassword(s.password)
	_, errWrite := s.writePacket(FINGERPRINT_COMMANDPACKET, payLoad)
	if errWrite != nil {
		ret = false
	}
	tp, errRead := s.readPacket()
	if errRead != nil {
		//Handle packet read error
	}
	if b, err := anyCommonErrors(tp); b == true {
		log.Printf(err.Error())
		ret = b
	}
	return ret
}

//SystemParameters -
type SystemParameters struct {
	StatusRegister  uint `struc:"uint16,big"`
	SystemID        uint `struc:"uint16,big"`
	StorageCapacity uint `struc:"uint16,big"`
	SecurityLevel   uint `struc:"uint16,big"`
	DeviceAddress   uint `struc:"uint32,big"`
	PacketLength    uint `struc:"uint16,big"`
	BaudRate        uint `struc:"uint16,big"`
}

func decodePayload(op interface{}, opBuf []byte) error {
	var err error
	buff := bytes.NewBuffer(opBuf[1:])
	err = struc.Unpack(buff, op)
	if err != nil {
		//Struc decode error
		op = nil
	}
	return err
}

func (s *scanner) GetSystemParameters() (*SystemParameters, error) {
	var err error

	payLoad := getPayloadForSystemParams()
	_, errWrite := s.writePacket(FINGERPRINT_COMMANDPACKET, payLoad)
	if errWrite != nil {
		return nil, errWrite
	}
	tp, errRead := s.readPacket()
	if errRead != nil {
		return nil, errRead
	}
	if b, err := anyCommonErrors(tp); b == true {
		log.Printf(err.Error())
		return nil, err
	}
	sp := &SystemParameters{}
	if err = decodePayload(sp, []byte(tp.PayLoad)); err != nil {
		sp = nil
	}
	return sp, err
}

func (s *scanner) ReadImage() bool {
	var ret bool
	ret = true
	payLoad := getPayloadForReadImage()
	_, errWrite := s.writePacket(FINGERPRINT_COMMANDPACKET, payLoad)
	if errWrite != nil {
		ret = false
	}

	tp, errRead := s.readPacket()
	if errRead != nil {
		//Handle packet read error
	}

	if b, err := anyCommonErrors(tp); b == true {
		log.Printf(err.Error())
		ret = b
	}
	return ret
}
