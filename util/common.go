package util

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type TLV struct {
	Tag    byte
	Length uint16
	Value  []byte
}

// Serialization Functions
func CreateSerializer() *bytes.Buffer {
	var buffer bytes.Buffer
	return &buffer
}

func Serialize(buffer *bytes.Buffer, value any) ([]byte, error) {
	if err := binary.Write(buffer, binary.BigEndian, value); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func TLV_serialize(buffer *bytes.Buffer, tlv *TLV) ([]byte, error) {
	Serialize(buffer, tlv.Tag)
	Serialize(buffer, tlv.Length)
	return Serialize(buffer, tlv.Value)
}

// Deserialization Functions
func CreateDeserializer(buffer []byte) *bytes.Reader {
	return bytes.NewReader(buffer)
}

func Deserialize(reader *bytes.Reader, value any) error {
	if err := binary.Read(reader, binary.BigEndian, value); err != nil {
		return err
	}
	return nil
}

func TLV_deserialize(reader *bytes.Reader) *TLV {
	var tlv TLV
	Deserialize(reader, &tlv.Tag)
	Deserialize(reader, &tlv.Length)
	tlv.Value = make([]byte, tlv.Length)
	Deserialize(reader, &tlv.Value)
	return &tlv
}

// TLV Code
func TLV_pack(tag byte, embed bool, value any) (*TLV, error) {
	if tag&0x80 != 0 {
		return nil, fmt.Errorf("tlv embed tag bit already set")
	}

	if embed {
		tag |= 0x80
	}

	buffer := CreateSerializer()
	payload, _ := Serialize(buffer, value)
	length := uint16(len(payload))
	return &TLV{Tag: tag, Length: length, Value: payload}, nil
}

func TLV_embedded(tlv *TLV) bool {
	return (tlv.Tag & 0x80) > 0
}

type USBDeviceID struct {
	VendorID  uint16
	ProductID uint16
}
