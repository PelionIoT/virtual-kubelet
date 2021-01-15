package main_test

import (
	"fmt"
	"testing"

	. "github.com/c1728p9/lwm2m"
)

type TLVResult struct {
	Type       TLVType
	Identifier int
	Length     int
	Children   []TLVResult
}

// 6.4.3.2 Multiple Object Instance Request Examples
var testDataMultiObject []byte = []byte{
	0x08, 0x00, 0x79,
	0xC8, 0x00, 0x14, 0x4F, 0x70, 0x65, 0x6E, 0x20, 0x4D, 0x6F, 0x62, 0x69, 0x6C, 0x65, 0x20, 0x41, 0x6C, 0x6C, 0x69, 0x61, 0x6E, 0x63, 0x65,
	0xC8, 0x01, 0x16, 0x4C, 0x69, 0x67, 0x68, 0x74, 0x77, 0x65, 0x69, 0x67, 0x68, 0x74, 0x20, 0x4D, 0x32, 0x4D, 0x20, 0x43, 0x6C, 0x69, 0x65, 0x6E, 0x74,
	0xC8, 0x02, 0x09, 0x33, 0x34, 0x35, 0x30, 0x30, 0x30, 0x31, 0x32, 0x33,
	0xC3, 0x03, 0x31, 0x2E, 0x30,
	0x86, 0x06,
	0x41, 0x00, 0x01,
	0x41, 0x01, 0x05,
	0x88, 0x07, 0x08,
	0x42, 0x00, 0x0E, 0xD8,
	0x42, 0x01, 0x13, 0x88,
	0x87, 0x08,
	0x41, 0x00, 0x7D,
	0x42, 0x01, 0x03, 0x84,
	0xC1, 0x09, 0x64,
	0xC1, 0x0A, 0x0F,
	0x83, 0x0B,
	0x41, 0x00, 0x00,
	0xC4, 0x0D, 0x51, 0x82, 0x42, 0x8F,
	0xC6, 0x0E, 0x2B, 0x30, 0x32, 0x3A, 0x30, 0x30,
	0xC1, 0x10, 0x55,
}

var testResultMultiObject TLVResult = TLVResult{
	Type:       ObjectInstance,
	Identifier: 0x00,
	Length:     121,
	Children: []TLVResult{
		{
			Type:       Resource,
			Identifier: 0x00,
			Length:     20,
			Children:   nil,
		},
		{
			Type:       Resource,
			Identifier: 0x01,
			Length:     22,
			Children:   nil,
		},
		{
			Type:       Resource,
			Identifier: 0x02,
			Length:     9,
			Children:   nil,
		},
		{
			Type:       Resource,
			Identifier: 0x03,
			Length:     3,
			Children:   nil,
		},
		{
			Type:       MultiResource,
			Identifier: 0x06,
			Length:     6,
			Children: []TLVResult{
				{
					Type:       ResourceInstance,
					Identifier: 0x00,
					Length:     1,
					Children:   nil,
				},
				{
					Type:       ResourceInstance,
					Identifier: 0x01,
					Length:     1,
					Children:   nil,
				},
			},
		},
		{
			Type:       MultiResource,
			Identifier: 0x07,
			Length:     8,
			Children: []TLVResult{
				{
					Type:       ResourceInstance,
					Identifier: 0x00,
					Length:     2,
					Children:   nil,
				},
				{
					Type:       ResourceInstance,
					Identifier: 0x01,
					Length:     2,
					Children:   nil,
				},
			},
		},
		{
			Type:       MultiResource,
			Identifier: 0x08,
			Length:     7,
			Children: []TLVResult{
				{
					Type:       ResourceInstance,
					Identifier: 0x00,
					Length:     1,
					Children:   nil,
				},
				{
					Type:       ResourceInstance,
					Identifier: 0x01,
					Length:     2,
					Children:   nil,
				},
			},
		},
		{
			Type:       Resource,
			Identifier: 0x09,
			Length:     1,
			Children:   nil,
		},
		{
			Type:       Resource,
			Identifier: 0x0A,
			Length:     1,
			Children:   nil,
		},
		{
			Type:       MultiResource,
			Identifier: 0x0B,
			Length:     3,
			Children: []TLVResult{
				{
					Type:       ResourceInstance,
					Identifier: 0x00,
					Length:     1,
					Children:   nil,
				},
			},
		},
		{
			Type:       Resource,
			Identifier: 0x0D,
			Length:     4,
			Children:   nil,
		},
		{
			Type:       Resource,
			Identifier: 0x0E,
			Length:     6,
			Children:   nil,
		},
		{
			Type:       Resource,
			Identifier: 0x10,
			Length:     1,
			Children:   nil,
		},
	},
}

func compareTLV(expected TLVResult, actual TLV) error {
	if expected.Type != actual.Type {
		return fmt.Errorf("Expected Type '%v', got '%v'", expected.Type, actual.Type)
	}
	if expected.Identifier != actual.Identifier {
		return fmt.Errorf("Expected Identifier '%v', got '%v'", expected.Identifier, actual.Identifier)
	}
	if expected.Length != len(actual.Value) {
		return fmt.Errorf("Expected Data Length '%v', got '%v'", expected.Length, len(actual.Value))
	}

	if len(expected.Children) != len(actual.Children) {
		return fmt.Errorf("Expected len(Children) '%v', got '%v'", len(expected.Children), len(actual.Children))
	}
	for i, expectedChild := range expected.Children {
		actualChild := actual.Children[i]
		childError := compareTLV(expectedChild, actualChild)
		if childError != nil {
			return fmt.Errorf("Child[%v] mismatch: %w", i, childError)
		}
	}
	return nil
}

func TestTLV(t *testing.T) {
	tlv, remain, err := TLVFromBytes(testDataMultiObject)
	if err != nil {
		t.Error(err)
	}

	err = compareTLV(testResultMultiObject, *tlv)
	if err != nil {
		t.Error(err)
	}

	tlv.Print()
	fmt.Printf("%v bytes remaining\n", len(remain))
}
