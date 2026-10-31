//go:build windows && (386 || arm)

package tunnel

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// FWPM_FILTER0 on 32-bit Windows (layout from wireguard-windows). Go aligns
// uint64 to 4 bytes here while MSVC aligns it to 8, hence the padding.
type fwpmFilter0 struct {
	filterKey           windows.GUID
	displayData         fwpmDisplayData0
	flags               uint32
	providerKey         *windows.GUID
	providerData        fwpByteBlob
	layerKey            windows.GUID
	subLayerKey         windows.GUID
	weight              fwpValue0
	numFilterConditions uint32
	filterCondition     *fwpmFilterCondition0
	action              fwpmAction0
	_                   [4]byte
	providerContextKey  windows.GUID
	reserved            *windows.GUID
	_                   [4]byte
	filterID            uint64
	effectiveWeight     fwpValue0
}

var (
	_ [unsafe.Sizeof(fwpmFilter0{}) - 152]struct{}
	_ [152 - unsafe.Sizeof(fwpmFilter0{})]struct{}
	_ [unsafe.Offsetof(fwpmFilter0{}.filterID) - 136]struct{}
	_ [136 - unsafe.Offsetof(fwpmFilter0{}.filterID)]struct{}
	_ [unsafe.Sizeof(fwpmFilterCondition0{}) - 28]struct{}
	_ [28 - unsafe.Sizeof(fwpmFilterCondition0{})]struct{}
	_ [unsafe.Sizeof(fwpmSession0{}) - 48]struct{}
	_ [48 - unsafe.Sizeof(fwpmSession0{})]struct{}
	_ [unsafe.Sizeof(fwpmSublayer0{}) - 44]struct{}
	_ [44 - unsafe.Sizeof(fwpmSublayer0{})]struct{}
	_ [unsafe.Sizeof(fwpmProvider0{}) - 40]struct{}
	_ [40 - unsafe.Sizeof(fwpmProvider0{})]struct{}
)
