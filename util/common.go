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

func TLV_pack(tag byte, embed bool, value interface{}) (*TLV, error) {
	var structBuf bytes.Buffer

	if tag&0x80 != 0 {
		return nil, fmt.Errorf("tlv embed tag bit already set")
	}

	if embed {
		tag |= 0x80
	}

	if err := binary.Write(&structBuf, binary.BigEndian, value); err != nil {
		return nil, err
	}

	payload := structBuf.Bytes()
	length := uint16(len(payload))

	return &TLV{Tag: tag, Length: length, Value: payload}, nil
}

func TLV_serialize(tlv *TLV) ([]byte, error) {
	var buf bytes.Buffer

	if err := buf.WriteByte(tlv.Tag); err != nil {
		return nil, err
	}

	if err := binary.Write(&buf, binary.BigEndian, tlv.Length); err != nil {
		return nil, err
	}

	if _, err := buf.Write(tlv.Value); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func TLV_deserialize(data []byte) (*TLV, error) {
	buf := bytes.NewReader(data)

	tag, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}

	var length uint16
	if err := binary.Read(buf, binary.BigEndian, &length); err != nil {
		return nil, err
	}

	value := make([]byte, length)
	if _, err := buf.Read(value); err != nil {
		return nil, err
	}

	return &TLV{Tag: tag, Length: length, Value: value}, nil
}

func TLV_unpack(tlv *TLV, out interface{}) error {
	buf := bytes.NewReader(tlv.Value)
	if err := binary.Read(buf, binary.BigEndian, out); err != nil {
		return err
	}

	return nil
}

func TLV_embedded(tlv *TLV) bool {
	return (tlv.Tag & 0x80) > 0
}

type USBDeviceID struct {
	VendorID  uint16
	ProductID uint16
}
