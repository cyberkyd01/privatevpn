//go:build windows

package tunnel

// Windows Filtering Platform back end for wfp_spec.go.
//
// Structure layouts, GUIDs and the filter scheme are taken from
// golang.zx2c4.com/wireguard/windows/tunnel/firewall (MIT, Copyright (C)
// 2019-2026 WireGuard LLC). That package cannot be used directly here: it
// only blocks DNS with doNotRestrict=false, requires a service SID in the
// process token (our helper is UAC-elevated, not a service) and keeps its
// objects in a dynamic session that dies with the process — the opposite of
// what a fail-closed kill switch needs.
//
// Two sessions are used:
//   - kill switch: a non-dynamic session adding PERSISTENT provider,
//     sublayer and filters with fixed keys. They survive the process, BFE
//     restarts and reboots; any later elevated process deletes them by key
//     (Down, `private-vpn-pro unblock`). Replacement happens inside one
//     transaction, so there is never a moment without a block.
//   - DNS-only leak protection (kill switch off): a dynamic session whose
//     filters vanish with the helper.

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modfwpuclnt                   = windows.NewLazySystemDLL("fwpuclnt.dll")
	procFwpmEngineOpen0           = modfwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0          = modfwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmProviderAdd0          = modfwpuclnt.NewProc("FwpmProviderAdd0")
	procFwpmProviderDeleteByKey0  = modfwpuclnt.NewProc("FwpmProviderDeleteByKey0")
	procFwpmSubLayerAdd0          = modfwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmSubLayerDeleteByKey0  = modfwpuclnt.NewProc("FwpmSubLayerDeleteByKey0")
	procFwpmFilterAdd0            = modfwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmFilterDeleteByKey0    = modfwpuclnt.NewProc("FwpmFilterDeleteByKey0")
	procFwpmFilterGetByKey0       = modfwpuclnt.NewProc("FwpmFilterGetByKey0")
	procFwpmTransactionBegin0     = modfwpuclnt.NewProc("FwpmTransactionBegin0")
	procFwpmTransactionCommit0    = modfwpuclnt.NewProc("FwpmTransactionCommit0")
	procFwpmTransactionAbort0     = modfwpuclnt.NewProc("FwpmTransactionAbort0")
	procFwpmGetAppIdFromFileName0 = modfwpuclnt.NewProc("FwpmGetAppIdFromFileName0")
	procFwpmFreeMemory0           = modfwpuclnt.NewProc("FwpmFreeMemory0")
)

// fwpCall invokes an Fwpm* function; they return a Win32 error code.
func fwpCall(p *windows.LazyProc, args ...uintptr) error {
	if err := p.Find(); err != nil {
		return err
	}
	r1, _, _ := syscall.SyscallN(p.Addr(), args...)
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

// fwpErrIs matches an FWP_E_* HRESULT returned by fwpCall.
func fwpErrIs(err error, code windows.Handle) bool {
	var e syscall.Errno
	return errors.As(err, &e) && uint32(e) == uint32(code)
}

// fwptypes.h / fwpmtypes.h
const (
	fwpUint8           = 1
	fwpUint16          = 2
	fwpUint32          = 3
	fwpUint64          = 4
	fwpByteArray16Type = 11
	fwpByteBlobType    = 12
	fwpV4AddrMask      = 0x100
	fwpV6AddrMask      = 0x101

	fwpMatchEqual       = 0
	fwpMatchFlagsAllSet = 6

	fwpActionBlock  = 0x00000001 | 0x00001000 // | FWP_ACTION_FLAG_TERMINATING
	fwpActionPermit = 0x00000002 | 0x00001000

	fwpmSessionFlagDynamic     = 0x00000001
	fwpmProviderFlagPersistent = 0x00000001
	fwpmSublayerFlagPersistent = 0x00000001
	fwpmFilterFlagPersistent   = 0x00000001
	rpcCAuthnWinNT             = 10

	fwpConditionFlagIsLoopback = 0x00000001
)

type fwpByteBlob struct {
	size uint32
	data *uint8
}

// FWP_VALUE0 / FWP_CONDITION_VALUE0: a 4-byte type tag and a pointer-sized union.
type fwpValue0 struct {
	typ   uint32
	value uintptr
}

type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

type fwpmFilterCondition0 struct {
	fieldKey       windows.GUID
	matchType      uint32
	conditionValue fwpValue0
}

type fwpmAction0 struct {
	typ        uint32
	filterType windows.GUID
}

type fwpmSession0 struct {
	sessionKey           windows.GUID
	displayData          fwpmDisplayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processID            uint32
	sid                  *windows.SID
	username             *uint16
	kernelMode           int32 // BOOL
}

type fwpmProvider0 struct {
	providerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerData fwpByteBlob
	serviceName  *uint16
}

type fwpmSublayer0 struct {
	subLayerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerKey  *windows.GUID
	providerData fwpByteBlob
	weight       uint16
}

// FWP_V4_ADDR_AND_MASK / FWP_V6_ADDR_AND_MASK (host byte order for v4).
type fwpV4AddrAndMask struct {
	addr uint32
	mask uint32
}

type fwpV6AddrAndMask struct {
	addr         [16]uint8
	prefixLength uint8
}

// fwpmFilter0 is defined per pointer size (wfp_windows_64.go / _32.go).

var (
	// fwpmu.h
	layerALEAuthConnectV4    = windows.GUID{Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33, Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}}
	layerALEAuthRecvAcceptV4 = windows.GUID{Data1: 0xe1cd9fe7, Data2: 0xf4b5, Data3: 0x4273, Data4: [8]byte{0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50}}
	layerALEAuthConnectV6    = windows.GUID{Data1: 0x4a72393b, Data2: 0x319f, Data3: 0x44bc, Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}}
	layerALEAuthRecvAcceptV6 = windows.GUID{Data1: 0xa3b42c97, Data2: 0x9f04, Data3: 0x4672, Data4: [8]byte{0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f}}

	condIPRemoteAddress  = windows.GUID{Data1: 0xb235ae9a, Data2: 0x1d64, Data3: 0x49b8, Data4: [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}}
	condIPLocalAddress   = windows.GUID{Data1: 0xd9ee00de, Data2: 0xc1ef, Data3: 0x4617, Data4: [8]byte{0xbf, 0xe3, 0xff, 0xd8, 0xf5, 0xa0, 0x89, 0x57}}
	condIPProtocol       = windows.GUID{Data1: 0x3971ef2b, Data2: 0x623e, Data3: 0x4f9a, Data4: [8]byte{0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7}}
	condIPLocalPort      = windows.GUID{Data1: 0x0c1ba1af, Data2: 0x5765, Data3: 0x453f, Data4: [8]byte{0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b}}
	condIPRemotePort     = windows.GUID{Data1: 0xc35a604d, Data2: 0xd22b, Data3: 0x4e1a, Data4: [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b}}
	condIPLocalInterface = windows.GUID{Data1: 0x4cd62a49, Data2: 0x59c3, Data3: 0x4969, Data4: [8]byte{0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4}}
	condALEAppID         = windows.GUID{Data1: 0xd78e1e87, Data2: 0x8644, Data3: 0x4ea5, Data4: [8]byte{0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71}}
	condFlags            = windows.GUID{Data1: 0x632ce23b, Data2: 0x5167, Data3: 0x435c, Data4: [8]byte{0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c}}
	// ICMP type/code share the port condition keys.
	condICMPType = condIPLocalPort
	condICMPCode = condIPRemotePort
)

// Layout checks shared by both pointer sizes (fail to compile on mismatch).
var (
	_ [unsafe.Sizeof(fwpmAction0{}) - 20]struct{}
	_ [20 - unsafe.Sizeof(fwpmAction0{})]struct{}
	_ [unsafe.Offsetof(fwpmFilterCondition0{}.matchType) - 16]struct{}
	_ [16 - unsafe.Offsetof(fwpmFilterCondition0{}.matchType)]struct{}
	_ [unsafe.Sizeof(fwpV4AddrAndMask{}) - 8]struct{}
	_ [8 - unsafe.Sizeof(fwpV4AddrAndMask{})]struct{}
	_ [unsafe.Sizeof(fwpV6AddrAndMask{}) - 17]struct{}
	_ [17 - unsafe.Sizeof(fwpV6AddrAndMask{})]struct{}
)

func layerGUID(l wfpLayer) windows.GUID {
	switch l {
	case wfpConnectV4:
		return layerALEAuthConnectV4
	case wfpRecvV4:
		return layerALEAuthRecvAcceptV4
	case wfpConnectV6:
		return layerALEAuthConnectV6
	}
	return layerALEAuthRecvAcceptV6
}

func fieldGUID(f wfpField) windows.GUID {
	switch f {
	case wfpFieldRemoteAddr:
		return condIPRemoteAddress
	case wfpFieldLocalAddr:
		return condIPLocalAddress
	case wfpFieldProtocol:
		return condIPProtocol
	case wfpFieldLocalPort:
		return condIPLocalPort
	case wfpFieldRemotePort:
		return condIPRemotePort
	case wfpFieldLocalInterface:
		return condIPLocalInterface
	case wfpFieldAppID:
		return condALEAppID
	case wfpFieldFlags:
		return condFlags
	case wfpFieldICMPType:
		return condICMPType
	}
	return condICMPCode
}

// wfpEngine is one BFE session.
type wfpEngine struct {
	h uintptr
}

func openWFPEngine(dynamic bool) (*wfpEngine, error) {
	name, err := windows.UTF16PtrFromString("Private VPN Pro")
	if err != nil {
		return nil, err
	}
	desc := "Private VPN Pro kill switch"
	if dynamic {
		desc = "Private VPN Pro DNS leak protection (dynamic)"
	}
	desc16, err := windows.UTF16PtrFromString(desc)
	if err != nil {
		return nil, err
	}
	session := fwpmSession0{
		displayData:          fwpmDisplayData0{name: name, description: desc16},
		txnWaitTimeoutInMSec: windows.INFINITE,
	}
	if dynamic {
		session.flags = fwpmSessionFlagDynamic
	}
	var h uintptr
	if err := fwpCall(procFwpmEngineOpen0, 0, rpcCAuthnWinNT, 0, uintptr(unsafe.Pointer(&session)), uintptr(unsafe.Pointer(&h))); err != nil {
		return nil, fmt.Errorf("WFP engine: %w", err)
	}
	runtime.KeepAlive(&session)
	return &wfpEngine{h: h}, nil
}

func (e *wfpEngine) close() {
	if e != nil && e.h != 0 {
		fwpCall(procFwpmEngineClose0, e.h)
		e.h = 0
	}
}

// transaction runs fn inside a BFE transaction (all or nothing).
func (e *wfpEngine) transaction(fn func() error) error {
	if err := fwpCall(procFwpmTransactionBegin0, e.h, 0); err != nil {
		return fmt.Errorf("WFP transaction: %w", err)
	}
	if err := fn(); err != nil {
		fwpCall(procFwpmTransactionAbort0, e.h)
		return err
	}
	if err := fwpCall(procFwpmTransactionCommit0, e.h); err != nil {
		fwpCall(procFwpmTransactionAbort0, e.h)
		return fmt.Errorf("WFP commit: %w", err)
	}
	return nil
}

// wfpArena owns the memory that condition values point to until the
// filters are added (BFE copies them during FwpmFilterAdd0).
type wfpArena struct {
	u64   []*uint64
	v4    []*fwpV4AddrAndMask
	v6    []*fwpV6AddrAndMask
	a16   []*[16]byte
	names []*uint16
	appID *fwpByteBlob
}

func (a *wfpArena) free() {
	if a.appID != nil {
		fwpCall(procFwpmFreeMemory0, uintptr(unsafe.Pointer(&a.appID)))
		a.appID = nil
	}
}

// loadAppID resolves this executable's WFP application id.
func (a *wfpArena) loadAppID() error {
	if a.appID != nil {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe16, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	if err := fwpCall(procFwpmGetAppIdFromFileName0, uintptr(unsafe.Pointer(exe16)), uintptr(unsafe.Pointer(&a.appID))); err != nil {
		return fmt.Errorf("WFP app id: %w", err)
	}
	if a.appID == nil {
		return errors.New("WFP app id: empty")
	}
	return nil
}

func (a *wfpArena) cond(c wfpCond) (fwpmFilterCondition0, error) {
	out := fwpmFilterCondition0{fieldKey: fieldGUID(c.Field), matchType: fwpMatchEqual}
	switch c.Kind {
	case wfpU8:
		out.conditionValue = fwpValue0{typ: fwpUint8, value: uintptr(c.Num)}
	case wfpU16:
		out.conditionValue = fwpValue0{typ: fwpUint16, value: uintptr(c.Num)}
	case wfpU32:
		out.conditionValue = fwpValue0{typ: fwpUint32, value: uintptr(c.Num)}
	case wfpU64:
		v := new(uint64)
		*v = c.Num
		a.u64 = append(a.u64, v)
		out.conditionValue = fwpValue0{typ: fwpUint64, value: uintptr(unsafe.Pointer(v))}
	case wfpV4Net:
		b := c.Prefix.Addr().As4()
		v := &fwpV4AddrAndMask{addr: uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])}
		if bits := c.Prefix.Bits(); bits > 0 {
			v.mask = ^uint32(0) << (32 - bits)
		}
		a.v4 = append(a.v4, v)
		out.conditionValue = fwpValue0{typ: fwpV4AddrMask, value: uintptr(unsafe.Pointer(v))}
	case wfpV6Net:
		v := &fwpV6AddrAndMask{addr: c.Prefix.Addr().As16(), prefixLength: uint8(c.Prefix.Bits())}
		a.v6 = append(a.v6, v)
		out.conditionValue = fwpValue0{typ: fwpV6AddrMask, value: uintptr(unsafe.Pointer(v))}
	case wfpV6Addr:
		v := new([16]byte)
		*v = c.Prefix.Addr().As16()
		a.a16 = append(a.a16, v)
		out.conditionValue = fwpValue0{typ: fwpByteArray16Type, value: uintptr(unsafe.Pointer(v))}
	case wfpAppID:
		if err := a.loadAppID(); err != nil {
			return out, err
		}
		out.conditionValue = fwpValue0{typ: fwpByteBlobType, value: uintptr(unsafe.Pointer(a.appID))}
	case wfpFlagsAllSet:
		out.matchType = fwpMatchFlagsAllSet
		out.conditionValue = fwpValue0{typ: fwpUint32, value: uintptr(c.Num)}
	default:
		return out, errors.New("WFP: unknown condition kind")
	}
	return out, nil
}

func (a *wfpArena) utf16(s string) (*uint16, error) {
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return nil, err
	}
	a.names = append(a.names, p)
	return p, nil
}

// addFilters adds the plan's filters. With persistent they get their
// deterministic keys, the PERSISTENT flag, the fixed provider and sublayer;
// otherwise BFE assigns keys and they belong to sublayer.
func (e *wfpEngine) addFilters(a *wfpArena, plan []wfpFilter, persistent bool, provider *windows.GUID, sublayer windows.GUID) error {
	if len(plan) > wfpMaxFilters {
		return errors.New("WFP: too many filters for the key range")
	}
	for i, f := range plan {
		name, err := a.utf16(f.Name)
		if err != nil {
			return err
		}
		conds := make([]fwpmFilterCondition0, 0, len(f.Conds))
		for _, c := range f.Conds {
			cc, err := a.cond(c)
			if err != nil {
				return err
			}
			conds = append(conds, cc)
		}
		filter := fwpmFilter0{
			displayData: fwpmDisplayData0{name: name, description: name},
			providerKey: provider,
			layerKey:    layerGUID(f.Layer),
			subLayerKey: sublayer,
			weight:      fwpValue0{typ: fwpUint8, value: uintptr(f.Weight)},
			action:      fwpmAction0{typ: fwpActionBlock},
		}
		if f.Permit {
			filter.action.typ = fwpActionPermit
		}
		if persistent {
			filter.filterKey = windows.GUID(wfpFilterKey(i))
			filter.flags = fwpmFilterFlagPersistent
		}
		if len(conds) > 0 {
			filter.numFilterConditions = uint32(len(conds))
			filter.filterCondition = &conds[0]
		}
		var id uint64
		err = fwpCall(procFwpmFilterAdd0, e.h, uintptr(unsafe.Pointer(&filter)), 0, uintptr(unsafe.Pointer(&id)))
		runtime.KeepAlive(conds)
		runtime.KeepAlive(&filter)
		if err != nil {
			return fmt.Errorf("WFP filter %q: %w", f.Name, err)
		}
	}
	return nil
}

// deleteFilterKeys removes keys 0..wfpMaxFilters-1 (missing ones are fine).
func (e *wfpEngine) deleteFilterKeys() error {
	for i := 0; i < wfpMaxFilters; i++ {
		k := windows.GUID(wfpFilterKey(i))
		err := fwpCall(procFwpmFilterDeleteByKey0, e.h, uintptr(unsafe.Pointer(&k)))
		runtime.KeepAlive(&k)
		if err != nil && !fwpErrIs(err, windows.FWP_E_FILTER_NOT_FOUND) {
			return fmt.Errorf("WFP delete filter: %w", err)
		}
	}
	return nil
}

// ---- persistent kill-switch block ----

// installPersistentBlock replaces our persistent filter set with the plan
// for spec in a single transaction.
func installPersistentBlock(spec wfpSpec) error {
	plan := buildWFPFilters(spec)
	e, err := openWFPEngine(false)
	if err != nil {
		return err
	}
	defer e.close()
	a := &wfpArena{}
	defer a.free()
	providerKey := windows.GUID(wfpProviderKey)
	sublayerKey := windows.GUID(wfpSublayerKey)
	name, err := a.utf16("Private VPN Pro")
	if err != nil {
		return err
	}
	desc, err := a.utf16("Private VPN Pro kill switch (removed by Disconnect or `private-vpn-pro unblock`)")
	if err != nil {
		return err
	}
	err = e.transaction(func() error {
		if err := e.deleteFilterKeys(); err != nil {
			return err
		}
		provider := fwpmProvider0{providerKey: providerKey, displayData: fwpmDisplayData0{name: name, description: desc}, flags: fwpmProviderFlagPersistent}
		if err := fwpCall(procFwpmProviderAdd0, e.h, uintptr(unsafe.Pointer(&provider)), 0); err != nil && !fwpErrIs(err, windows.FWP_E_ALREADY_EXISTS) {
			return fmt.Errorf("WFP provider: %w", err)
		}
		runtime.KeepAlive(&provider)
		sublayer := fwpmSublayer0{subLayerKey: sublayerKey, displayData: fwpmDisplayData0{name: name, description: desc},
			flags: fwpmSublayerFlagPersistent, providerKey: &providerKey, weight: ^uint16(0)}
		if err := fwpCall(procFwpmSubLayerAdd0, e.h, uintptr(unsafe.Pointer(&sublayer)), 0); err != nil && !fwpErrIs(err, windows.FWP_E_ALREADY_EXISTS) {
			return fmt.Errorf("WFP sublayer: %w", err)
		}
		runtime.KeepAlive(&sublayer)
		return e.addFilters(a, plan, true, &providerKey, sublayerKey)
	})
	runtime.KeepAlive(a)
	return err
}

// removePersistentBlock deletes our persistent filters (one transaction),
// then the sublayer and provider. Missing objects are fine.
func removePersistentBlock() error {
	e, err := openWFPEngine(false)
	if err != nil {
		return err
	}
	defer e.close()
	if err := e.transaction(e.deleteFilterKeys); err != nil {
		return err
	}
	sublayerKey := windows.GUID(wfpSublayerKey)
	if err := fwpCall(procFwpmSubLayerDeleteByKey0, e.h, uintptr(unsafe.Pointer(&sublayerKey))); err != nil &&
		!fwpErrIs(err, windows.FWP_E_SUBLAYER_NOT_FOUND) && !fwpErrIs(err, windows.FWP_E_IN_USE) {
		return fmt.Errorf("WFP delete sublayer: %w", err)
	}
	providerKey := windows.GUID(wfpProviderKey)
	if err := fwpCall(procFwpmProviderDeleteByKey0, e.h, uintptr(unsafe.Pointer(&providerKey))); err != nil &&
		!fwpErrIs(err, windows.FWP_E_PROVIDER_NOT_FOUND) && !fwpErrIs(err, windows.FWP_E_IN_USE) {
		return fmt.Errorf("WFP delete provider: %w", err)
	}
	runtime.KeepAlive(&sublayerKey)
	runtime.KeepAlive(&providerKey)
	return nil
}

// persistentBlockInstalled probes the first persistent key (every kill
// switch plan starts with it).
func persistentBlockInstalled() bool {
	e, err := openWFPEngine(false)
	if err != nil {
		return false
	}
	defer e.close()
	k := windows.GUID(wfpFilterKey(0))
	var f *fwpmFilter0
	err = fwpCall(procFwpmFilterGetByKey0, e.h, uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(&f)))
	runtime.KeepAlive(&k)
	if err != nil {
		return false
	}
	fwpCall(procFwpmFreeMemory0, uintptr(unsafe.Pointer(&f)))
	return true
}

// ---- dynamic DNS-only blocker (kill switch off) ----

// dnsBlocker owns one dynamic WFP session (filters die with the process).
type dnsBlocker struct {
	engine *wfpEngine
}

// newDNSBlocker blocks DNS (UDP/TCP port 53, IPv4 and IPv6) except to
// allowed (the tunnel resolver) and except for our own executable — the
// dual-role gateway's DNS forwarder in the main process queries the saved
// physical resolvers (§7.4), and it is the same private-vpn-pro.exe.
func newDNSBlocker(allowed []netip.Addr) (*dnsBlocker, error) {
	plan := buildWFPFilters(wfpSpec{DNS: allowed})
	e, err := openWFPEngine(true)
	if err != nil {
		return nil, err
	}
	a := &wfpArena{}
	defer a.free()
	sublayerKey, err := windows.GenerateGUID()
	if err != nil {
		e.close()
		return nil, err
	}
	name, err := a.utf16("Private VPN Pro DNS leak protection")
	if err != nil {
		e.close()
		return nil, err
	}
	err = e.transaction(func() error {
		sublayer := fwpmSublayer0{subLayerKey: sublayerKey, displayData: fwpmDisplayData0{name: name, description: name}, weight: ^uint16(0)}
		if err := fwpCall(procFwpmSubLayerAdd0, e.h, uintptr(unsafe.Pointer(&sublayer)), 0); err != nil {
			return fmt.Errorf("WFP sublayer: %w", err)
		}
		runtime.KeepAlive(&sublayer)
		return e.addFilters(a, plan, false, nil, sublayerKey)
	})
	runtime.KeepAlive(a)
	if err != nil {
		e.close()
		return nil, err
	}
	return &dnsBlocker{engine: e}, nil
}

func (b *dnsBlocker) close() {
	if b != nil {
		b.engine.close()
	}
}
