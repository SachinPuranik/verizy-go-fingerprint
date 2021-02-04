package fingerprint

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lunixbochs/struc"
)

//ThumbPacket  -
type ThumbPacket struct {
	StartCode      uint `struc:"uint16,big"`
	Address        uint `struc:"uint32,big"`
	PacketType     uint `struc:"uint8,big"`
	PacketLength   uint `struc:"uint16,big"`
	PayLoad        string
	PacketChecksum uint `struc:"int16,big"`
}

func calculateChecksum(packetType int, packetLength int, packetPayload []byte) int {
	//Calculate Checksum , By rotating and adding Liitle Endian
	packetChecksum := packetType + packetLength>>8 /*Shift Right 8*/ + packetLength>>0 /*Shift Right 0*/
	//Write payload
	for _, b := range packetPayload {
		packetChecksum += int(b)
	}
	return packetChecksum
}

func buildCommandPacket(packetType int, packetPayload []byte) []byte {

	var buf bytes.Buffer

	tp := &ThumbPacket{}
	tp.StartCode = FINGERPRINT_STARTCODE
	tp.Address = 0xFFFFFFFF //0x00000002
	tp.PacketType = uint(packetType)
	tp.PayLoad = string(packetPayload)

	packetLength := len(packetPayload) + 2 //2 Is for last 2 bytes of checksum
	//Calculate Checksum , By rotating and adding Liitle Endian
	packetChecksum := packetType + packetLength>>8 /*Shift Right 8*/ + packetLength>>0 /*Shift Right 0*/

	//Write payload
	for _, b := range packetPayload {
		packetChecksum += int(b)
	}

	tp.PacketChecksum = uint(calculateChecksum(packetType, packetLength, packetPayload))
	tp.PacketLength = uint(packetLength)

	err := struc.Pack(&buf, tp)

	if err != nil {
		fmt.Println("Ohhh its error ->", err)
	}

	return buf.Bytes()
}

func verifyChecksum(tp *ThumbPacket) error {
	var err error
	checkSum := uint(calculateChecksum(int(tp.PacketType), int(tp.PacketLength), []byte(tp.PayLoad)))
	if tp.PacketChecksum != checkSum {
		err = errors.New("Checksum match error")
	}
	return err
}

func decodeResponsePacket(opBuf []byte) (*ThumbPacket, error) {
	var err error
	op := new(ThumbPacket)
	buff := bytes.NewBuffer(opBuf)
	err = struc.Unpack(buff, op)
	if err != nil {
		//Struc decode error
		op = nil
	}
	//We are doing this as struc does not understand the payload length here.
	l := len(opBuf)
	op.PayLoad = string(opBuf[9 : l-2])
	chksum := uint16(opBuf[l-2]) << 8
	chksum = chksum | uint16(opBuf[l-1])
	op.PacketChecksum = uint(chksum)
	return op, err
}

func strucToBytes(pl interface{}) []byte {
	var payLoad bytes.Buffer
	err := struc.Pack(&payLoad, pl)

	if err != nil {
		fmt.Println("Ohhh its error=>", err)
	}
	return payLoad.Bytes()
}

//systemParams -
type simplePayLoadStruc struct {
	PayLoadType uint `struc:"int8,big"`
}

func getPayloadForSystemParams() []byte {
	pl := &simplePayLoadStruc{}
	pl.PayLoadType = FINGERPRINT_GETSYSTEMPARAMETERS
	return strucToBytes(pl)
}

// passwordStruc -
type passwordStruc struct {
	PayLoadType uint `struc:"int8,big"`
	Password    uint `struc:"int32,big"`
}

func getPayloadForVerifyPassword(pwd uint) []byte {
	pl := &passwordStruc{}
	pl.PayLoadType = FINGERPRINT_VERIFYPASSWORD
	pl.Password = pwd
	return strucToBytes(pl)

}

func getPayloadForSetPassword(pwd uint) []byte {
	pl := &passwordStruc{}
	pl.PayLoadType = FINGERPRINT_SETPASSWORD
	pl.Password = pwd
	return strucToBytes(pl)
}

func createTemplatePayload() []byte {
	pl := &simplePayLoadStruc{}
	pl.PayLoadType = FINGERPRINT_CREATETEMPLATE
	return strucToBytes(pl)
}

func getTemplateCountPayload() []byte {
	pl := &simplePayLoadStruc{}
	pl.PayLoadType = FINGERPRINT_READIMAGE
	return strucToBytes(pl)
}

func readImagePayload() []byte {
	pl := &simplePayLoadStruc{}
	pl.PayLoadType = FINGERPRINT_READIMAGE
	return strucToBytes(pl)
}

//get templateIndex
type templateIndexStruc struct {
	PayLoadType int `struc:"int8,big"`
	Page        int `struc:"int8,big"`
}

func templateIndexPayload(page int) []byte {
	pl := &templateIndexStruc{}
	pl.PayLoadType = FINGERPRINT_TEMPLATEINDEX
	pl.Page = page
	return strucToBytes(pl)
}

func downloadImagePayload() []byte {
	pl := &simplePayLoadStruc{}
	pl.PayLoadType = FINGERPRINT_DOWNLOADIMAGE
	return strucToBytes(pl)
}

func clearDatabasePayload() []byte {
	pl := &simplePayLoadStruc{}
	pl.PayLoadType = FINGERPRINT_CLEARDATABASE
	return strucToBytes(pl)
}

func compareCharacteristicsPayload() []byte {

	pl := &simplePayLoadStruc{}
	pl.PayLoadType = FINGERPRINT_COMPARECHARACTERISTICS
	return strucToBytes(pl)

}

func generateRandomNumberPayload() []byte {

	pl := &simplePayLoadStruc{}
	pl.PayLoadType = FINGERPRINT_GENERATERANDOMNUMBER
	return strucToBytes(pl)

}

type searchImageStruc struct {
	PayLoadType   int `struc:"int8,big"`
	CharBufferNo  int `struc:"int8,big"`
	StartPos      int `struc:"int16,big"`
	TemplateCount int `struc:"int16,big"`
}

func searchImagePayload(charBufferNo int, startPos int, count int) []byte {
	pl := &searchImageStruc{}
	pl.PayLoadType = FINGERPRINT_SEARCHTEMPLATE
	pl.CharBufferNo = charBufferNo
	pl.StartPos = startPos
	pl.TemplateCount = count
	return strucToBytes(pl)
}

type setAddressStruc struct {
	PayLoadType int `struc:"int8,big"`
	NewAddress  int `struc:"int32,big"`
}

func setAddressPayload(adds int) []byte {
	pl := &setAddressStruc{}
	pl.PayLoadType = FINGERPRINT_SETADDRESS
	pl.NewAddress = adds
	return strucToBytes(pl)
}

type convertImageStruc struct {
	PayLoadType  int `struc:"int8,big"`
	CharBufferNo int `struc:"int8,big"`
}

func convertImagePayload(charBufferNo int) []byte {
	pl := &convertImageStruc{}
	pl.PayLoadType = FINGERPRINT_CONVERTIMAGE
	pl.CharBufferNo = charBufferNo
	return strucToBytes(pl)
}

type storeTemplateSturc struct {
	PayLoadType    int `struc:"int8,big"`
	PositionNumber int `struc:"int16,big"`
	CharBufferNo   int `struc:"int8,big"`
}

func storeTemplatePayload(Position int, CharBufferNo int) []byte {

	pl := &storeTemplateSturc{}
	pl.PayLoadType = FINGERPRINT_STORETEMPLATE
	pl.PositionNumber = Position
	pl.CharBufferNo = CharBufferNo
	return strucToBytes(pl)

}

type loadTemplatestruc struct {
	PayLoadType    int `struc:"int8,big"`
	CharBufferNo   int `struc:"int8,big"`
	PositionNumber int `struc:"int16,big"`
}

func loadTemplatePayload(Position int, CharBufferNo int) []byte {

	pl := &loadTemplatestruc{}
	pl.PayLoadType = FINGERPRINT_LOADTEMPLATE
	pl.CharBufferNo = CharBufferNo
	pl.PositionNumber = Position
	return strucToBytes(pl)

}

type deleteTemplateStruc struct {
	PayLoadType    int `struc:"int8,big"`
	PositionNumber int `struc:"int16,big"`
	Count          int `struc:"int16,big"`
}

func deleteTemplatePayload(Position int, cnt int) []byte {
	pl := &deleteTemplateStruc{}
	pl.PayLoadType = FINGERPRINT_DELETETEMPLATE
	pl.PositionNumber = Position
	pl.Count = cnt
	return strucToBytes(pl)

}

type downloadCharacteristicsStruc struct {
	PayLoadType  int `struc:"int8,big"`
	CharBufferNo int `struc:"int8,big"`
}

func downloadCharacteristicsPayload(CharBufferNo int) []byte {
	pl := &downloadCharacteristicsStruc{}
	pl.PayLoadType = FINGERPRINT_DOWNLOADCHARACTERISTICS
	pl.CharBufferNo = CharBufferNo

	return strucToBytes(pl)

}

type setPasswordStruc struct {
	PayLoadType int `struc:"int8,big"`
	NEWPassword int `struc:"int32,big"`
}

func setPasswordPayload(pass int) []byte {
	pl := &setPasswordStruc{}
	pl.PayLoadType = FINGERPRINT_SETPASSWORD
	pl.NEWPassword = pass
	return strucToBytes(pl)

}

func checkUnpack(payLoad []byte) {
	b := bytes.NewBuffer(payLoad)
	o := &searchImageStruc{}
	struc.Unpack(b, o)
	out, _ := json.Marshal(o)
	fmt.Printf(string(out))
}
