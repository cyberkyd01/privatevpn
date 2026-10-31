//go:build windows && (amd64 || arm64)

package tunnel

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// FWPM_FILTER0 on 64-bit Windows (layout from wireguard-windows, verified
// there against the SDK headers).
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
	_                   [4]byte // the providerContextKey union is 8-aligned
	providerContextKey  windows.GUID
	reserved            *windows.GUID
	filterID            uint64
	effectiveWeight     fwpValue0
}

// Compile-time layout checks (an out-of-range array length fails the build).
var (
	_ [unsafe.Sizeof(fwpmFilter0{}) - 200]struct{}
	_ [200 - unsafe.Sizeof(fwpmFilter0{})]struct{}
	_ [unsafe.Offsetof(fwpmFilter0{}.weight) - 96]struct{}
	_ [96 - unsafe.Offsetof(fwpmFilter0{}.weight)]struct{}
	_ [unsafe.Offsetof(fwpmFilter0{}.action) - 128]struct{}
	_ [128 - unsafe.Offsetof(fwpmFilter0{}.action)]struct{}
	_ [unsafe.Offsetof(fwpmFilter0{}.providerContextKey) - 152]struct{}
	_ [152 - unsafe.Offsetof(fwpmFilter0{}.providerContextKey)]struct{}
	_ [unsafe.Offsetof(fwpmFilter0{}.filterID) - 176]struct{}
	_ [176 - unsafe.Offsetof(fwpmFilter0{}.filterID)]struct{}
	_ [unsafe.Sizeof(fwpmFilterCondition0{}) - 40]struct{}
	_ [40 - unsafe.Sizeof(fwpmFilterCondition0{})]struct{}
	_ [unsafe.Offsetof(fwpmFilterCondition0{}.conditionValue) - 24]struct{}
	_ [24 - unsafe.Offsetof(fwpmFilterCondition0{}.conditionValue)]struct{}
	_ [unsafe.Sizeof(fwpmSession0{}) - 72]struct{}
	_ [72 - unsafe.Sizeof(fwpmSession0{})]struct{}
	_ [unsafe.Offsetof(fwpmSession0{}.sid) - 48]struct{}
	_ [48 - unsafe.Offsetof(fwpmSession0{}.sid)]struct{}
	_ [unsafe.Sizeof(fwpmSublayer0{}) - 72]struct{}
	_ [72 - unsafe.Sizeof(fwpmSublayer0{})]struct{}
	_ [unsafe.Offsetof(fwpmSublayer0{}.weight) - 64]struct{}
	_ [64 - unsafe.Offsetof(fwpmSublayer0{}.weight)]struct{}
	_ [unsafe.Sizeof(fwpmProvider0{}) - 64]struct{}
	_ [64 - unsafe.Sizeof(fwpmProvider0{})]struct{}
	_ [unsafe.Offsetof(fwpmProvider0{}.providerData) - 40]struct{}
	_ [40 - unsafe.Offsetof(fwpmProvider0{}.providerData)]struct{}
	_ [unsafe.Offsetof(fwpmProvider0{}.serviceName) - 56]struct{}
	_ [56 - unsafe.Offsetof(fwpmProvider0{}.serviceName)]struct{}
	_ [unsafe.Sizeof(fwpValue0{}) - 16]struct{}
	_ [16 - unsafe.Sizeof(fwpValue0{})]struct{}
)
