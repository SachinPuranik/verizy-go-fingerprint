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
	ctxt   *gousb.Context
	device *gousb.Device
	config *gousb.Config
	intf   *gousb.Interface
	epIn   *gousb.InEndpoint
	epOut  *gousb.OutEndpoint
	vid    gousb.ID
	pid    gousb.ID
}

type mySerial struct {
	port *serial.Port
	cfg  *serial.Config
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

//Scanner - Scanner struct to hold various data members
type scanner struct {
	usb       myUSB
	serial    mySerial
	useSerial bool
	password  uint
	debug     bool
	param     *SystemParameters
}

//ScannerIO - Interface for Scanner
type ScannerIO interface {
	Capture() error
	Release()
	VerifyPassword() bool
	GetSystemParameters() (*SystemParameters, error)
	ReadImage() bool
	DeleteFingerprint(position int, count int) bool
	ConvertImage(charBufferNo int) bool
	SearchTemplate(charBufferNo int, startPos int, count int) (*SearchResult, error)
	CreateTemplate() error
	StoreTemplate(Position int, CharBufferNo int) (int, error)
	ClearDatabase() error
	CompareCharacteristics() (int, error)
}

// func getDefaultSerialCfg() *serial.Config {
// 	return &serial.Config{Name: "/dev/tty.usbserial-1420", Baud: 9600 * 6, ReadTimeout: time.Millisecond * 500}
// }

//NewSerial - Create Scanner with serial connection
func NewSerial(serialCfg *serial.Config, password uint) ScannerIO {
	if serialCfg == nil {
		log.Fatal("Unable to open serial port due to invalid params")
	}

	s := &scanner{}
	s.serial.cfg = serialCfg
	s.useSerial = true
	s.password = password
	return s
}

//NewUSB - Create Scanner with usb connection
func NewUSB(vid uint16, pid uint16, password uint) ScannerIO {
	s := &scanner{}
	// Open any device with a given VID/PID using a convenience function.
	s.usb.vid = gousb.ID(vid)
	s.usb.pid = gousb.ID(pid)
	s.useSerial = false
	s.password = password
	return s
}

func (s *scanner) captureSerial() error {
	var err error
	s.serial.port, err = serial.OpenPort(s.serial.cfg)
	if err != nil {
		log.Printf(err.Error())
		return err
	}
	return nil
}

func (s *scanner) captureUSB() error {
	var err error
	s.usb.ctxt = gousb.NewContext()
	s.usb.device, err = s.usb.ctxt.OpenDeviceWithVIDPID(s.usb.vid, s.usb.pid)
	if err != nil {
		s.usb.ctxt.Close()
		log.Printf("Could not open a device: %v\n", err)
		return err
	}

	// Switch the configuration to #1.
	s.usb.config, err = s.usb.device.Config(1)
	if err != nil {
		log.Printf("%s.Config(2): %v", s.usb.device, err)
		s.usb.device.Close()
		s.usb.ctxt.Close()
		return err
	}
	// In the config #2, claim interface #3 with alt setting #0.
	s.usb.intf, err = s.usb.config.Interface(0, 0)
	if err != nil {
		log.Fatalf("%s.Interface(0, 0): %v", s.usb.device, err)
		s.usb.device.Close()
		s.usb.device.Close()
		s.usb.ctxt.Close()
		return err
	}

	s.usb.epIn, err = s.usb.intf.InEndpoint(2)
	if err != nil {
		log.Fatalf("%s.InEndpoint(2): %v", s.usb.intf, err)
		s.usb.intf.Close()
		s.usb.device.Close()
		s.usb.device.Close()
		s.usb.ctxt.Close()
		return err
	}

	// And in the same interface open endpoint #5 for writing.
	s.usb.epOut, err = s.usb.intf.OutEndpoint(2)
	if err != nil {
		log.Fatalf("%s.InEndpoint(2): %v", s.usb.intf, err)
		s.usb.intf.Close()
		s.usb.device.Close()
		s.usb.device.Close()
		s.usb.ctxt.Close()
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
	if err == nil {
		s.param, err = s.GetSystemParameters()
	}
	return err
}

func (s *scanner) releaseSerial() {

}

func (s *scanner) releaseUSB() {

	s.usb.intf.Close()
	s.usb.device.Close()
	s.usb.device.Close()
	s.usb.ctxt.Close()
}

func (s *scanner) Release() {
	if s.useSerial == true {
		s.releaseSerial()
	} else {
		s.releaseUSB()
	}
}

func (s *scanner) getStorageCapacity() int {
	return int(s.param.StorageCapacity)
}

func (s *scanner) writeSerial(payLoad []byte) (int, error) {
	numBytes, err := s.serial.port.Write(payLoad)
	if numBytes == 0 {
		// log.Printf("%d.Write(): only %d bytes written, returned error is %v\n", s.serial.port, numBytes, err)
		return -1, err
	}
	return numBytes, err
}

func (s *scanner) writeUSB(payLoad []byte) (int, error) {
	// Write data to the USB device.
	numBytes, err := s.usb.epOut.Write(payLoad)
	if numBytes == 0 {
		log.Printf("%s.Write([2]): only %d bytes written, returned error is %v\n", s.usb.epOut, numBytes, err)
		numBytes = -1
	}
	return numBytes, err
}

func (s *scanner) writePacket(packetType int, payLoad []byte) (numBytes int, err error) {
	packet := buildCommandPacket(packetType, payLoad)
	if s.debug == true {
		fmt.Println("Final Packet: ", packet)
	}
	if s.useSerial == true {
		numBytes, err = s.writeSerial(packet)
	} else {
		numBytes, err = s.writeUSB(packet)
	}
	return numBytes, err
}

func (s *scanner) readFragementOnSerial(readSize int) ([]byte, int, error) {

	buf := make([]byte, readSize)
	readBytes, err := s.serial.port.Read(buf)
	if err != nil {
		log.Printf("Error reading Serial Port =>%s\n", err.Error())
		readBytes = -1
		buf = nil
	}
	return buf, readBytes, err
}

func (s *scanner) readFragementOnUSB(readSize int) ([]byte, int, error) {
	buf := make([]byte, readSize)
	readBytes, err := s.usb.epIn.Read(buf)
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

		if readBytes > 0 {
			buf = append(buf, frag[:readBytes]...)
		}

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
	if s.debug == true {
		fmt.Println("Final Received Packet: ", buf)
	}
	err = verifyChecksum(tp)
	return tp, err
}

func anyCommonErrors(tp *ThumbPacket) (errorFound bool, errorCode int, errDesc error) {

	errorFound = true //Yes there is error
	errDesc = nil

	if tp.PacketType != FINGERPRINT_ACKPACKET {
		errDesc = errors.New("the received packet is no ack packet")
	}

	receivedPacketPayload := []byte(tp.PayLoad)
	errorCode = int(receivedPacketPayload[0])

	if errorCode == FINGERPRINT_OK && errDesc == nil {
		errorFound = false
		errDesc = nil
	} else if errorCode == FINGERPRINT_ERROR_COMMUNICATION {
		errDesc = errors.New("Communication error")
	} else if errorCode == FINGERPRINT_ERROR_INVALIDREGISTER {
		errDesc = errors.New("Invalid register number")
	} else if errorCode == FINGERPRINT_ERROR_MESSYIMAGE {
		errDesc = errors.New("The image is too messy")
	} else if errorCode == FINGERPRINT_ERROR_FEWFEATUREPOINTS {
		errDesc = errors.New("The image contains too few feature points")
	} else if errorCode == FINGERPRINT_ERROR_INVALIDIMAGE {
		errDesc = errors.New("The image is invalid")
	} else if errorCode == FINGERPRINT_ERROR_CHARACTERISTICSMISMATCH {
		errDesc = errors.New("characteristics mismatch")
	} else if errorCode == FINGERPRINT_ERROR_NOTMATCHING {
		errDesc = errors.New("Fingerprint do not mismatch")
	} else if errorCode == FINGERPRINT_ERROR_CLEARDATABASE {
		errDesc = errors.New("Unable to clear database")
	} else if errorCode == FINGERPRINT_ERROR_INVALIDPOSITION {
		errDesc = errors.New("Invalid position")
	} else if errorCode == FINGERPRINT_ERROR_DELETETEMPLATE {
		errDesc = errors.New("Delete operation failed")
	} else if errorCode == FINGERPRINT_ERROR_NOTEMPLATEFOUND {
		errorFound = false
		errDesc = nil
	} else if errorCode == FINGERPRINT_ERROR_NOFINGER {
		errorFound = false
		errDesc = nil
	} else {
		errDesc = errors.New("Unknownon error occured")
	}
	return errorFound, errorCode, errDesc
}

func (s *scanner) VerifyPassword() (ret bool) {
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
	if errorFound, _, errDesc := anyCommonErrors(tp); errDesc != nil {
		log.Printf(errDesc.Error())
		ret = !errorFound
	}
	return ret
}

func (s *scanner) SetPassword(password uint) (ret bool) {

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
	if errorFound, _, errDesc := anyCommonErrors(tp); errDesc != nil {
		log.Printf(errDesc.Error())
		ret = !errorFound
	}
	return ret
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
	if _, _, errDesc := anyCommonErrors(tp); errDesc != nil {
		log.Printf(err.Error())
		return nil, errDesc
	}
	result := &SystemParameters{}
	if err = decodePayload(result, []byte(tp.PayLoad)); err != nil {
		result = nil
	}
	return result, err
}

func (s *scanner) ReadImage() (ret bool) {
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

	var errorFound bool
	var errorCode int
	var errDesc error

	if errorFound, errorCode, errDesc = anyCommonErrors(tp); errDesc != nil {
		log.Printf(errDesc.Error())
		ret = !errorFound
	}
	if errorCode == FINGERPRINT_ERROR_NOFINGER {
		ret = false
	}
	return ret
}

func (s *scanner) ConvertImage(charBufferNo int) bool {
	var ret bool
	ret = true
	payLoad := getPayloadForConvertImage(charBufferNo)
	_, errWrite := s.writePacket(FINGERPRINT_COMMANDPACKET, payLoad)
	if errWrite != nil {
		ret = false
	}

	tp, errRead := s.readPacket()
	if errRead != nil {
		//Handle packet read error
	}

	if errorFound, _, errDesc := anyCommonErrors(tp); errDesc != nil {
		log.Printf(errDesc.Error())
		ret = !errorFound
	}
	return ret
}

//SearchResult -
type SearchResult struct {
	PositionNumber int `struc:"uint16,big"`
	AccuracyScore  int `struc:"uint16,big"`
}

func (s *scanner) SearchTemplate(charBufferNo int, startPos int, count int) (*SearchResult, error) {
	var err error
	var errorFound bool
	var errorCode int
	var errDesc error

	if charBufferNo != FINGERPRINT_CHARBUFFER1 && charBufferNo != FINGERPRINT_CHARBUFFER2 {
		err = errors.New("the given charbuffer number is invalid")
		return nil, err
	}

	templatesCount := 0
	if count > 0 {
		templatesCount = count
	} else {
		templatesCount = s.getStorageCapacity()
	}

	payLoad := getPayloadForSearchImage(charBufferNo, startPos, templatesCount)
	_, errWrite := s.writePacket(FINGERPRINT_COMMANDPACKET, payLoad)
	if errWrite != nil {
		return nil, errWrite
	}

	responsePacket, errRead := s.readPacket()
	if errRead != nil {
		return nil, errRead
	}

	if errorFound, errorCode, errDesc = anyCommonErrors(responsePacket); errDesc != nil {
		log.Printf(errDesc.Error())
		return nil, err
	}

	result := &SearchResult{-1, -1}

	if errorFound == false && errorCode == FINGERPRINT_ERROR_NOTEMPLATEFOUND {
		return result, errDesc
	}

	if err = decodePayload(result, []byte(responsePacket.PayLoad)); err != nil {
		result = nil
	}
	return result, err
}

//Accuracy -
type Accuracy struct {
	Score int `struc:"uint16,big"`
}

func (s *scanner) CompareCharacteristics() (int, error) {
	var errDesc error

	payLoad := getPayloadForCompareCharacteristics()
	_, errWrite := s.writePacket(FINGERPRINT_COMMANDPACKET, payLoad)
	if errWrite != nil {
		return 0, errWrite
	}

	responsePacket, errRead := s.readPacket()
	if errRead != nil {
		//Handle packet read error
		return 0, errRead
	}

	if _, _, errDesc = anyCommonErrors(responsePacket); errDesc != nil {
		return 0, errDesc
	}

	result := &Accuracy{}
	if errDesc = decodePayload(result, []byte(responsePacket.PayLoad)); errDesc != nil {
		result.Score = 0
	}
	return result.Score, errDesc
}

func (s *scanner) CreateTemplate() error {

	payLoad := getPayloadForCreateTemplate()
	_, errWrite := s.writePacket(FINGERPRINT_COMMANDPACKET, payLoad)
	if errWrite != nil {
		return errWrite
	}

	responsePacket, errRead := s.readPacket()
	if errRead != nil {
		//Handle packet read error
		return errRead
	}

	if _, _, errDesc := anyCommonErrors(responsePacket); errDesc != nil {
		log.Printf(errDesc.Error())
		return errDesc
	}

	return nil
}

func (s *scanner) getFreePosition() int {
	freePosition := -1

	for page := 0; page <= 3; page++ {
		if freePosition >= 0 {
			break
		}
		templateIndex, err := s.getTemplateIndex(page)
		if err != nil {
			return freePosition
		}
		for index := range templateIndex {
			if templateIndex[index] == false {
				freePosition = (len(templateIndex) * page) + index
				break
			}
		}
	}
	return freePosition
}

//StoreTemplate -
func (s *scanner) StoreTemplate(Position int, CharBufferNo int) (int, error) {

	if Position == -1 {
		Position = s.getFreePosition()
	}

	if Position < 0x0000 || Position >= s.getStorageCapacity() {
		return -1, errors.New("The given position number is invalid")
	}

	if CharBufferNo != FINGERPRINT_CHARBUFFER1 && CharBufferNo != FINGERPRINT_CHARBUFFER2 {
		return -1, errors.New("the given char buffer number is invalid")
	}

	payLoad := getPayloadForStoreTemplate(Position, CharBufferNo)
	_, errWrite := s.writePacket(FINGERPRINT_COMMANDPACKET, payLoad)
	if errWrite != nil {
		return -1, errWrite
	}

	responsePacket, errRead := s.readPacket()
	if errRead != nil {
		//Handle packet read error
		return -1, errRead
	}

	if _, _, errDesc := anyCommonErrors(responsePacket); errDesc != nil {
		log.Printf(errDesc.Error())
		return -1, errDesc
	}

	return Position, nil
}

func (s *scanner) getTemplateIndex(page int) ([]bool, error) {

	templateIndex := make([]bool, 0)

	payLoad := getPayloadForTemplateIndex(page)
	_, errWrite := s.writePacket(FINGERPRINT_COMMANDPACKET, payLoad)
	if errWrite != nil {
		return nil, errWrite
	}

	responsePacket, errRead := s.readPacket()
	if errRead != nil {
		//Handle packet read error
		return nil, errRead
	}

	if _, _, errDesc := anyCommonErrors(responsePacket); errDesc != nil {
		log.Printf(errDesc.Error())
		return nil, errDesc
	}

	pageElements := []byte(responsePacket.PayLoad)[1:]

	for _, pageElement := range pageElements {
		for b := 0; b <= 7; b++ {
			positionIsUsed := (pageElement & (0x01 << b)) != 0
			templateIndex = append(templateIndex, positionIsUsed)
		}
	}

	return templateIndex, nil
}

func (s *scanner) ClearDatabase() error {

	payLoad := getPayloadForClearDatabase()
	_, errWrite := s.writePacket(FINGERPRINT_COMMANDPACKET, payLoad)
	if errWrite != nil {
		return errWrite
	}

	responsePacket, errRead := s.readPacket()
	if errRead != nil {
		//Handle packet read error
		return errRead
	}

	if _, _, errDesc := anyCommonErrors(responsePacket); errDesc != nil {
		log.Printf(errDesc.Error())
		return errDesc
	}

	return nil
}

//DeleteFingerprint
func (s *scanner) DeleteFingerprint(position int, count int) bool {
	var ret bool
	ret = true

	if count < 1 {
		return false
	}

	payLoad := getPayloadForDeleteTemplate(position, count)
	_, errWrite := s.writePacket(FINGERPRINT_COMMANDPACKET, payLoad)
	if errWrite != nil {
		ret = false
	}

	tp, errRead := s.readPacket()
	if errRead != nil {
		//Handle packet read error
	}

	if errorFound, _, errDesc := anyCommonErrors(tp); errDesc != nil {
		log.Printf(errDesc.Error())
		ret = !errorFound
	}

	return ret
}
