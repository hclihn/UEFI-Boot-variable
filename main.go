package main

import (
	"fmt"
  "os"
  "io"
  "bytes"
  "strings"
  "path/filepath"
  "encoding/binary"
  "encoding/hex"
  "unicode/utf16"
  "regexp"
)

const debug = false
const useEFIVarFS = true

// const efiVarDir = "/sys/firmware/efi/vars"

// deprecated efivars
const efiVarsDir = "test/vars"
// new efivarfs
const efiVarFSDir = "test/efivars"

var (
  hasEFIVarFS = false
	efiVarDir   = ""
)

func init() {
  if useEFIVarFS {
    hasEFIVarFS = true
	  efiVarDir   = efiVarFSDir
  } else {
    hasEFIVarFS = false
	  efiVarDir   = efiVarsDir
  }
}

func GetEFIVarData(name string) ([]byte, string, error) {
  ptn := fmt.Sprintf("%s-*", name)
  m, err := filepath.Glob(filepath.Join(efiVarDir, ptn))
  if err != nil {
    return nil, "", fmt.Errorf("failed to find %q in EFI Variable dir %q: %w", ptn, efiVarDir, err)
  }
  switch len(m) {
  case 0:
    return nil, "", fmt.Errorf("failed to find %q in EFI Variable dir %q: nothing found", ptn, efiVarDir)
  case 1: 
    // ok, fall through
  default:
    return nil, "", fmt.Errorf("failed to find %q in EFI Variable dir %q: too many found: %q", ptn, efiVarDir, m)
  }
  // Read data
  thePath := m[0]
	if !hasEFIVarFS {
		thePath = filepath.Join(m[0], "data")
	}
  data, err := os.ReadFile(thePath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read %s file %q: %w", name, thePath, err)
	}
  if debug {
    fmt.Println(thePath)
    fmt.Println(hex.Dump(data))
  }
  return data, thePath, nil
}

func GetEFIUint(data []byte, bits int) (uint64, int, error) {
  if bits%8 != 0 {
    return 0, 0, fmt.Errorf("failed to get EFI uint: bits (%d) are not multiple of 8", bits)
  }
  nb := bits / 8
  if nb == 0 {
    return 0, 0, nil
  } else if len(data) < nb {
    return 0, 0, fmt.Errorf("failed to get EFI uint%d: insufficient data (%d bytes), expected %d", bits, len(data), nb)
  }
  var val uint64 = uint64(data[nb-1])
  for i := nb-2; i >= 0; i-- {
    val = val * 256 + uint64(data[i])
  }
  return val, nb, nil
}

func GetEFIBootOrder() ([]int, error) {
  data, thePath, err := GetEFIVarData("BootOrder")
	if err != nil {
		return nil, fmt.Errorf("failed to get BootOrder data: %w", err)
	}
  if hasEFIVarFS { // strip off the leading 4-byte attribute
		data = data[4:]
	}
  // the data is a list of little-endian uint16 numbers
  l := len(data)
  if l%2 != 0 {
    return nil, fmt.Errorf("failed to read BootOrder data in %q: data length (%d) is not a multiple of 2", thePath, l)
  }
  bootOrder := make([]int, l/2)
  for i := 0; i < l-1; i+=2 {
    bootOrder[i/2] = int(data[i]) + int(data[i+1]) * 256
  }
  return bootOrder, nil
}

func GetEFIBootCurrent() (int, error) {
  data, thePath, err := GetEFIVarData("BootCurrent")
	if err != nil {
		return -1, fmt.Errorf("failed to get BootCurrent data: %w", err)
	}
  if hasEFIVarFS { // strip off the leading 4-byte attribute
		data = data[4:]
	}
  // the data is a little-endian uint16 number
  l := len(data)
  if l != 2 {
    return -1, fmt.Errorf("failed to read BootCurrent data in %q: data length (%d) is not 2", thePath, l)
  }
  bootCurrent, _, err := GetEFIUint(data, 16)
  return int(bootCurrent), err
}

func GetEFIString(r io.Reader) (string, int, error) {
  var code uint16
  var buf [2]byte
	br := 0
	codes := make([]uint16, 0)
	for {
    n, err := r.Read(buf[:])
    br += n
    if n != 2 {
      if err != nil {
        return "", br, fmt.Errorf("failed to get EFI string with %d bytes returned while expecting 2: %w", n, err)
      } else {
        return "", br, fmt.Errorf("failed to get EFI string with %d bytes returned while expecting 2", n)
      }
    }
		code = uint16(buf[0]) + uint16(buf[1])*256
		if code == 0 { // end-of-string indicator
			break
		}
		codes = append(codes, code)
	}
	rs := utf16.Decode(codes)
  return string(rs), br, nil
} 

func GetEFIGUID(data []byte) (string, int, error) {
  if len(data) < 16 {
    return "", 0, fmt.Errorf("failed to get EFI GUID: insufficient data (%d bytes), expected 16", len(data))
  }
  var buf strings.Builder
  nRead := 0
  // first part: 4 bytes, littel endian
  val, nr, err := GetEFIUint(data, 32)
  if err != nil {
    return "", 0, fmt.Errorf("failed to get EFI GUID part 1 (4 bytes): %w", err)
  }
  nRead += nr
  fmt.Fprintf(&buf, "%08x-", val)
  // 2nd part: 2 bytes, little endian
  val, nr, err = GetEFIUint(data[nRead:], 16)
  if err != nil {
    return "", 0, fmt.Errorf("failed to get EFI GUID part 2 (2 bytes): %w", err)
  }
  nRead += nr
  fmt.Fprintf(&buf, "%04x-", val)
  // 3rd part: 2 bytes, little endian
  val, nr, err = GetEFIUint(data[nRead:], 16)
  if err != nil {
    return "", 0, fmt.Errorf("failed to get EFI GUID part 3 (2 bytes): %w", err)
  }
  nRead += nr
  fmt.Fprintf(&buf, "%04x-", val)
  // 4th part: 2 bytes, big endian
  for i := 0; i < 2; i++ {
    fmt.Fprintf(&buf, "%02x", data[nRead]) 
    nRead++
  }
  buf.WriteByte('-')
  // 5th part: 6 bytes, big endian
  for i := 0; i < 6; i++ {
    fmt.Fprintf(&buf, "%02x", data[nRead]) 
    nRead++
  }
  return buf.String(), nRead, nil
}

// EFIDevicePathProtocol defines the header part of EFI Device Path Node data
// EFI_DEVICE_PATH_PROTOCOL is defined in section 9.2 of the UEFI 2.6 spec
type EFIDevicePathProtocol struct {
  TheType uint8 // UINT8 Type
  SubType uint8 // UINT8 SubType
  Length uint16 // UINT8 Length[2]
}

func (p EFIDevicePathProtocol) CombinedType() int {
  return int(p.TheType) * 256 + int(p.SubType)
}

// EFIDPNodePropertyMap
type EFIDPNodePropertyMap map[string]string

// EFIDevicePathNode defines the data stored in FilePathList
// EFI Device Path Node is defined in section 9.3 of the UEFI 2.6 spec
type EFIDevicePathNode struct {
  EFIDevicePathProtocol
  Data []byte
  Properties EFIDPNodePropertyMap // if len is 0, then it's not parsed
}

func (f EFIDevicePathNode) ToString(nIndent, level int) string {
  indent := strings.Repeat(" ", nIndent*level)
  indent2 := strings.Repeat(" ", nIndent*(level+1))
  indent3 := strings.Repeat(" ", nIndent*(level+2))
  var buf strings.Builder
  fmt.Fprintf(&buf, "%sEFIDevicePathNode {\n", indent)
  fmt.Fprintf(&buf, "%stype=%d, subtype=%d, length=%d\n", indent2, f.TheType, f.SubType, f.Length)
  
  if len(f.Properties) > 0 {
    fmt.Fprintf(&buf, "%sProperties:\n", indent2)
    for k, v := range f.Properties {
      fmt.Fprintf(&buf, "%s%s = %s\n", indent3, k, v)
    }
  } else if len(f.Data) > 0 {
    fmt.Fprintf(&buf, "%sData:\n", indent2)
    fmt.Fprintf(&buf, "%s\n", hex.Dump(f.Data))
  }
  fmt.Fprintf(&buf, "%s}\n", indent)
  return buf.String()
}

func (f EFIDevicePathNode) String() string {
  return f.ToString(0, 0)
}

type EFILoadOptionAttr uint32

const (
  EFOLoadOptionActive EFILoadOptionAttr = 1 // LOAD_OPTION_ACTIVE = 0x00000001
  EFOLoadOptionForceRecon EFILoadOptionAttr = 2 // LOAD_OPTION_FORCE_RECONNECT = 0x00000002
  EFOLoadOptionHidden EFILoadOptionAttr = 8 // LOAD_OPTION_HIDDEN = 0x00000008
)

// EFILoadOption defines teh EFI load option for boot
// EFI_LOAD_OPTION is defined in section 3.1.3 of the UEFI 2.6 spec
type EFILoadOption struct {
  Attributes EFILoadOptionAttr // UINT32 Attributes
  FilePathListLen uint16 // UINT16 FilePathListLength
  Description string // CHAR16 Description[]
  FilePathList []EFIDevicePathNode // EFI_DEVICE_PATH_PROTOCOL FilePathList[]
  OptionalData []uint8 // UINT8 OptionalData[]
}

func (l EFILoadOption) String() string {
  const nIndent = 2
  indent := strings.Repeat(" ", nIndent)
  var buf strings.Builder
  buf.WriteString("EFILoadOption {\n")
  fmt.Fprintf(&buf, "%sAttributes: 0x%08x,\n", indent, l.Attributes)
  fmt.Fprintf(&buf, "%sDescription: %q,\n", indent, l.Description)
  fmt.Fprintf(&buf, "%sFilePathList: items=%d; length=%d bytes\n", indent, len(l.FilePathList), l.FilePathListLen)
  for i, node := range l.FilePathList {
    fmt.Fprintf(&buf, "%s%sFilePathList[%d]:\n", indent, indent, i)
    buf.WriteString(node.ToString(nIndent, 3))
  }
  fmt.Fprintf(&buf, "%sOptionalData: %d,\n", indent, l.OptionalData)
  buf.WriteString("}\n")
  return buf.String()
}

func (l *EFILoadOption) Parse(data []byte) error {
  buf := bytes.NewReader(data)
  bytesParsed := 0
  var nr int
  var err error
  // get Attributes
  if err = binary.Read(buf, binary.LittleEndian, &l.Attributes); err != nil {
		return fmt.Errorf("failed to parse EFILoadOption.Attributes: %w", err)
	}
  bytesParsed += 4
  // get FilePathListLength
  if err = binary.Read(buf, binary.LittleEndian, &l.FilePathListLen); err != nil {
		return fmt.Errorf("failed to parse EFILoadOption.FilePathListLength: %w", err)
	}
  bytesParsed += 2
  // get Description
  l.Description, nr, err = GetEFIString(buf)
  if err != nil {
		return fmt.Errorf("failed to parse EFILoadOption.Description: %w", err)
	}
  bytesParsed += nr
  optDataOffset := bytesParsed + int(l.FilePathListLen)
  // parse FilePathList
  l.FilePathList = make([]EFIDevicePathNode, 0)
  for i := 0; bytesParsed < optDataOffset; i++ {
    var h EFIDevicePathProtocol
    if err = binary.Read(buf, binary.LittleEndian, &h); err != nil {
  		return fmt.Errorf("failed to parse EFILoadOption.FilePathList[%d].EFIDevicePathProtocol: %w", i, err)
  	}
    bytesParsed += 4
    if h.CombinedType() == EFIEndDevicePath {
      break
    }
    dLen := int(h.Length) - 4
    var d []byte
    if dLen > 0 {
      d = make([]byte, dLen)
      nr, err = buf.Read(d)
      if nr != dLen {
        return fmt.Errorf("failed to read EFILoadOption.FilePathList[%d] data with %d bytes returned while expecting %d: %w", i, nr, dLen, err)
      }
    }
    m, err := ParseDevicePathNode(d, h)
    if err != nil {
      return fmt.Errorf("failed to parse EFILoadOption.FilePathList[%d] data: %w", i, err)
    }
    l.FilePathList = append(l.FilePathList, EFIDevicePathNode{
      EFIDevicePathProtocol: h, 
      Data: d,
      Properties: m,
    })
    bytesParsed += nr
  }
  // parse OptionalData
  nOptData := len(data) - optDataOffset
  l.OptionalData = make([]byte, nOptData)
  nr, err = buf.ReadAt(l.OptionalData, int64(optDataOffset))
  if nr != nOptData {
    return fmt.Errorf("failed to read EFILoadOption.OptionalData with %d bytes returned while expecting %d: %w", nr, nOptData, err)
  }
  return nil
}

func (l EFILoadOption) GetDPTypeProperty(dpType int, prop string) (hasType, hasProp bool, val string) {
  var b strings.Builder
  for _, node := range l.FilePathList {
    if node.CombinedType() != dpType {
      continue
    }
    hasType = true
    v, ok := node.Properties[prop]
    if !ok {
      continue
    }
    hasProp = true
    b.WriteString(v)
  }
  val = b.String()
  return
}

const (
  // types
  // EFIHardwareDevicePathType (0x01xx), Sec 9.3.2
  // EFIAcpiDevicePathType (0x02xx), Sec 9.3.3 and 9.3.4
  // EFIMessagingDevicePathType (0x03xx), Sec 9.3.5
  // EFIMediaDevicePathType (0x04xx), Sec 9.3.6
  EFIMediaHarddriveDevicePath = 0x0401
  EFIMediaFilePathDevicePath = 0x0404
  // EFIBIOSBootSpecDevicePathType (0x05xx), Sec 9.3.7
  // EFIEndDevicePathType, Sec 9.3.1
  EFIEndDevicePath = 0x7fff
)

type EFIDeviceTypeParser func([]byte, EFIDPNodePropertyMap) error

var efiDeviceTypeParserMap = map[int]EFIDeviceTypeParser{
  EFIMediaHarddriveDevicePath: ParseMediaHardriveDP,
  EFIMediaFilePathDevicePath: ParseMediaFilePathDP,
}

func ParseDevicePathNode(data []byte, h EFIDevicePathProtocol) (EFIDPNodePropertyMap, error) {
  if len(data) == 0 {
    return nil, nil
  }
  m := make(EFIDPNodePropertyMap)
  if fn, ok := efiDeviceTypeParserMap[h.CombinedType()]; ok {
    if err := fn(data, m); err != nil {
        return nil, fmt.Errorf("failed to parse DevicePathNode for type %d subtype %d: %w", h.TheType, h.SubType, err)
      }
  }
  
  if len(m) == 0 {
    return nil, nil
  }
  return m, nil
}

func ParseMediaFilePathDP(data []byte, m EFIDPNodePropertyMap) error {
  buf := bytes.NewReader(data)
  s, _, err := GetEFIString(buf)
  if err != nil {
    return fmt.Errorf("failed to parse MediaFilePathDP: %w", err)
  }
  m["PathNameRaw"] = s
  s = strings.ReplaceAll(s, "\\", "/")
  if strings.HasPrefix(s, "/EFI/") {
    s = "/EFI/"+ strings.ToLower(s[5:])
  }
  m["PathName"] = s
  return nil
}

func ParseMediaHardriveDP(data []byte, m EFIDPNodePropertyMap) error {
  nRead := 0
  // UINT32 PartitionNumber
  val, nr, err := GetEFIUint(data, 32)
  if err != nil {
    return fmt.Errorf("failed to parse MediaHardriveDP.PartitionNumber: %w", err)
  }
  nRead += nr
  m["PartitionNumber"] = fmt.Sprintf("%d", val)
  // UINT64 PartitionStart
  val, nr, err = GetEFIUint(data[nRead:], 64)
  if err != nil {
    return fmt.Errorf("failed to parse MediaHardriveDP.PartitionStart: %w", err)
  }
  nRead += nr
  m["PartitionStart"] = fmt.Sprintf("%d", val)
  // UINT64 PartitionSize
  val, nr, err = GetEFIUint(data[nRead:], 64)
  if err != nil {
    return fmt.Errorf("failed to parse MediaHardriveDP.PartitionSize: %w", err)
  }
  nRead += nr
  m["PartitionSize"] = fmt.Sprintf("%d", val)
  // UINT8 Signature[16]
  sigOffset := nRead
  nRead += 16
  // UINT8 MBRType (Partition Format)
  partType := int(data[nRead])
  switch partType {
  case 1:
    m["PartitionFormat"] = "MBR"
  case 2:
    m["PartitionFormat"] = "GPT"
  default:
    return fmt.Errorf("failed to parse MediaHardriveDP.PartitionFormat: unknown partition format %d", partType)
  }
  nRead++
  // UINT8 SignatureType
  sigType := int(data[nRead])
  m["SignatureType"] = fmt.Sprintf("%d", sigType)
  switch sigType {
  case 0:
    // no signature, no-op
    m["SignatureTypeString"] = "No Signature"
    m["PartitionSignature"] = ""
  case 1: // first 4 bytes as little endian uint 32
    val, _, err = GetEFIUint(data[sigOffset:], 32)
    if err != nil {
      return fmt.Errorf("failed to parse MediaHardriveDP.Signature for SignatureType %d: %w", sigType, err)
    }
    m["PartitionSignature"] = fmt.Sprintf("0x%08x", val)
    m["SignatureTypeString"] = "MBR Signature"
  case 2:
    s, _, err := GetEFIGUID(data[sigOffset:])
    if err != nil {
      return fmt.Errorf("failed to parse MediaHardriveDP.Signature for SignatureType %d: %w", sigType, err)
    }
    m["PartitionSignature"] = s
    m["SignatureTypeString"] = "GUID Signature"
  default:
    return fmt.Errorf("undefined MediaHardriveDP.SignatureType %d", sigType)
  }
  return nil
}

// Reference: https://uefi.org/sites/default/files/resources/UEFI%20Spec%202_6.pdf
// Sec 2.3.1 defines all data types
// https://github.com/Bareflank/gnu-efi/blob/master/inc/efidevp.h

func GetEFIBootItem(idx int) (*EFILoadOption, error) {
  name := fmt.Sprintf("Boot%04X", idx) // upper-case 4-digit hex! 
  data, thePath, err := GetEFIVarData(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get %s data: %w", name, err)
	}
  fmt.Println(thePath)
  fmt.Println(hex.Dump(data))
  if hasEFIVarFS { // strip off the leading 4-byte attribute
		data = data[4:]
	}
  var loadOpt EFILoadOption
  if err := loadOpt.Parse(data); err != nil {
		return nil, fmt.Errorf("failed to parse %s EFILoadOption from %q: %w", name, thePath, err)
	}
  return &loadOpt, nil
}

func GetCurrentEFIDiskBootPath() (string, error) {
  index, err := GetEFIBootCurrent()
  if err != nil {
    return "", fmt.Errorf("failed to get current EFI disk boot path while getting BootCurrent: %w", err)
  }
  loadOpt, err := GetEFIBootItem(index)
  if err != nil {
    return "", fmt.Errorf("failed to get current EFI disk boot path while getting Boot%04X: %w", index, err)
  }
  hasType, hasProp, sig := loadOpt.GetDPTypeProperty(EFIMediaHarddriveDevicePath, "PartitionSignature")
	if !hasType {
		return "", fmt.Errorf("failed to get current EFI disk boot info: missing EFIMediaHarddriveDevicePath node in Boot%04X data", index)
	} else if !hasProp {
		return "", fmt.Errorf("failed to get current EFI disk boot info: missing EFIMediaHarddriveDevicePath node property 'PartitionSignature' in Boot%04X data", index)
	}
  hasType, hasProp, val := loadOpt.GetDPTypeProperty(EFIMediaFilePathDevicePath, "PathName")
  if !hasType {
     return "", fmt.Errorf("failed to get current EFI disk boot path: missing MediaFilePathDevicePath in Boot%04X data", index)
  } else if !hasProp {
    return "", fmt.Errorf("failed to get current EFI disk boot path: missing MediaFilePathDevicePath property FilePath in Boot%04X data", index)
  }
  return fmt.Sprintf("%s:%s", sig, val), nil
}

type FindInfo struct {
	Path string
	Info os.FileInfo
}

// GetFinalTarget gets the final target path for the Path component
// If Path is a symlink, it will follow it to the end and return a path to that final target
func (f FindInfo) GetFinalTarget() (string, error) {
	if f.Info.Mode()&os.ModeSymlink == 0 { // not a symlink
		return f.Path, nil
	} else if path, err := filepath.EvalSymlinks(f.Path); err != nil { // follow the link to the end
		return "", fmt.Errorf("failed to resolve symbolic link %q: %w", f.Path, err)
	} else {
		return path, nil
	}
}

func FindFile(root string, patterns []string, usePath bool) (found map[string][]FindInfo, err error) {
	ptn := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		ptn[i], err = regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regular expression %q for FindFile: %w", p, err)
		}
	}
	f := make(map[string][]FindInfo) // this will work with the same filename at different locations
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("failed to traverse to %q for FindFile: %w", path, err)
		}
		for _, p := range ptn {
			name := info.Name() // file name
			if usePath {
				name = path
			}
			if p.MatchString(name) { // append the finding
				f[name] = append(f[name], FindInfo{
					Path: path,
					Info: info,
				})
				break
			}
		}
		return nil
	})
	if len(f) > 0 {
		found = f
	}
	return found, err
}

func main() {
  /*
    "Boot0000-venHw-ubuntu",
    "Boot0001-8be4df61-93ca-11d2-aa0d-00e098032b8c",
    "Boot0002-PXE-IPv4.data",
    "Boot0004-venMedia-UEFI-shell",
    "Boot0005-PXE-IPv6.data",
    "Boot0006-8be4df61-93ca-11d2-aa0d-00e098032b8c",
    "Boot0007-Virtual-CD-ROM.data",
    "BootCurrent-8be4df61-93ca-11d2-aa0d-00e098032b8c",
    "BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c",
  */
  if useEFIVarFS {
    fmt.Println("***** Use new efivarfs *****")
  } else {
    fmt.Println("***** Use legacy sysfs EFI vars *****")
  }
	bo, err := GetEFIBootOrder()
  if err != nil {
    fmt.Println("ERROR:", err)
    return
  }
  fmt.Printf("Boot Order: %d\n", bo)
  bc, err := GetEFIBootCurrent()
  if err != nil {
    fmt.Println("ERROR:", err)
    return
  }
  fmt.Printf("Boot Current: %d\n", bc)
  loadOpt, err := GetEFIBootItem(1)
  if err != nil {
    fmt.Println("ERROR:", err)
    return
  }
  fmt.Println(loadOpt)
  fmt.Println(GetCurrentEFIDiskBootPath())

  fmt.Println(FindFile("/home/runner/UEFI-Boot-variable", []string{`/Boot0004-[^/]+/data`}, true))
}
