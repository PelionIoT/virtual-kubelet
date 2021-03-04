package main

import "fmt"

// TLVType is the type of TLV
type TLVType int

const (
	// ObjectInstance is a LWM2M object instance. It contains zero or more Resource and MultiResource
	ObjectInstance = 0
	// ResourceInstance is a resource entry of a MultiResource
	ResourceInstance = 1
	// MultiResource contains one or more ResourceInstance
	MultiResource = 2
	// Resource is a LWM2M resource
	Resource = 3
)

func (t TLVType) String() string {
	switch t {
	case ObjectInstance:
		return "Object Instance"
	case ResourceInstance:
		return "Resource Instance"
	case MultiResource:
		return "Multiple Resource"
	case Resource:
		return "Resource"
	default:
		return "Invalid"
	}
}

// TLV is a parsed LWM2M TLV entry
type TLV struct {
	Type       TLVType
	Identifier int
	Value      []byte
	Children   []TLV
}

// TLVFromBytes loads a TLV from the given bytes
func TLVFromBytes(data []byte) (*TLV, []byte, error) {
	t := TLV{}

	if len(data) < 1 {
		return nil, nil, fmt.Errorf("Data short to be a valid TLV")
	}

	typeField := int(data[0])
	t.Type = TLVType((data[0] >> 6) & 0x3)
	data = data[1:]

	if typeField&(1<<5) == 0 {
		if len(data) < 1 {
			return nil, nil, fmt.Errorf("Data short to be a valid TLV")
		}
		t.Identifier = int(data[0])
		data = data[1:]
	} else {
		if len(data) < 2 {
			return nil, nil, fmt.Errorf("Data short to be a valid TLV")
		}
		t.Identifier = (int(data[0]) << 8) | (int(data[1]) << 0)
		data = data[2:]
	}

	lengthBytes := (typeField >> 3) & 0x3
	length := 0
	if lengthBytes == 0 {

		// No length field, the value immediately follows the Identifier field in is of the length indicated by Bits 2-0 of this field
		length = (typeField >> 0) & 0x7
	} else {

		// The Length field is lengthBytes and Bits 2-0 MUST be ignored
		if len(data) < lengthBytes {
			return nil, nil, fmt.Errorf("Data short to be a valid TLV. Needed %v, got %v", lengthBytes, len(data))
		}
		for i := 0; i < lengthBytes; i++ {
			length = (length << 8) | int(data[i])
		}
		data = data[lengthBytes:]
	}
	if len(data) < length {
		return nil, nil, fmt.Errorf("Data short to be a valid TLV. Needed %v, got %v", length, len(data))
	}
	t.Value = make([]byte, length)
	copy(t.Value, data)
	data = data[length:]

	if (t.Type == ObjectInstance) || (t.Type == MultiResource) {
		childData := t.Value
		for len(childData) > 0 {
			var child *TLV
			var err error
			child, childData, err = TLVFromBytes(childData)
			if err != nil {
				return nil, nil, err
			}
			t.Children = append(t.Children, *child)
		}
	}

	return &t, data, nil
}

func (t *TLV) String() string {
	return fmt.Sprintf("Type='%v', ID=%v, Size=%v, Children=%v", t.Type, t.Identifier, len(t.Value), len(t.Children))
}

// Print displays the TLV
func (t *TLV) Print() {
	t.print("")
}

func (t *TLV) print(prefix string) {
	fmt.Printf("%v%v\n", prefix, t)
	for _, child := range t.Children {
		child.print(prefix + "  ")
	}
}
