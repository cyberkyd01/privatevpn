// Command icons generates every Private VPN Pro icon from code: the five tray
// states (idle, gateway on, connected, both, warning) in colour (PNG, ICO) and as
// macOS template images, plus the application icon for Windows (go-winres
// input, installer .ico), Linux (.desktop) and macOS (.icns).
//
// Run from the repository root:  go run ./build/icons
//
// Shapes are signed-distance style predicates evaluated with 4×4
// supersampling, so the output is anti-aliased and fully deterministic.
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"log"
	"math"
	"os"
	"path/filepath"
)

// rgba is a non-premultiplied colour with components in [0,1].
type rgba struct{ r, g, b, a float64 }

func hex(h uint32) rgba {
	return rgba{float64(h>>16&0xff) / 255, float64(h>>8&0xff) / 255, float64(h&0xff) / 255, 1}
}

var (
	transparent = rgba{}
	white       = rgba{1, 1, 1, 1}
	black       = rgba{0, 0, 0, 1}
	grey        = hex(0x8c95a5)
	blue        = hex(0x2f6fed)
	blueDark    = hex(0x1f56c7)
	green       = hex(0x18a058)
	greenDark   = hex(0x10804a)
	amber       = hex(0xe08a00)
	amberDark   = hex(0xc07400)
)

// painter returns the colour at (x, y) in unit coordinates (y down).
type painter func(x, y float64) rgba

// --- geometry (unit square) ---

const (
	shTop    = 0.07 // shield top at the centre line
	shDip    = 0.08 // how much lower the top corners are
	shHalf   = 0.37 // half width of the straight part
	shWaist  = 0.50 // where the sides start to curve in
	shBottom = 0.95 // tip
)

// shieldHalfWidth returns the half width of the shield at height y.
func shieldHalfWidth(y float64) float64 {
	if y <= shWaist {
		return shHalf
	}
	t := (y - shWaist) / (shBottom - shWaist)
	if t >= 1 {
		return 0
	}
	return shHalf * math.Pow(math.Cos(math.Pi/2*t), 0.85)
}

func shieldTop(x float64) float64 {
	u := (x - 0.5) / shHalf
	return shTop + shDip*u*u
}

// inShield reports whether (x, y) is inside the shield shrunk by inset.
func inShield(x, y, inset float64) bool {
	if y > shBottom-inset*1.6 {
		return false
	}
	if y < shieldTop(x)+inset {
		return false
	}
	return math.Abs(x-0.5) <= shieldHalfWidth(y)-inset
}

func inCircle(x, y, cx, cy, r float64) bool { return (x-cx)*(x-cx)+(y-cy)*(y-cy) <= r*r }

// inKeyhole: a round head and a tapering slot.
func inKeyhole(x, y float64) bool {
	if inCircle(x, y, 0.5, 0.41, 0.095) {
		return true
	}
	if y >= 0.43 && y <= 0.69 {
		t := (y - 0.43) / 0.26
		return math.Abs(x-0.5) <= 0.038+0.03*t
	}
	return false
}

// inWaves: a dot with two arcs above it ("broadcasting").
func inWaves(x, y float64) bool {
	cx, cy := 0.5, 0.60
	if inCircle(x, y, cx, cy, 0.062) {
		return true
	}
	dx, dy := x-cx, y-cy
	d := math.Hypot(dx, dy)
	ang := math.Atan2(dx, -dy) // 0 = straight up
	if math.Abs(ang) > 0.95 {
		return false
	}
	for _, r := range []float64{0.17, 0.285} {
		if math.Abs(d-r) <= 0.033 {
			return true
		}
	}
	return false
}

// inExclaim: an exclamation mark ("connection interrupted / blocked").
func inExclaim(x, y float64) bool {
	if inCircle(x, y, 0.5, 0.675, 0.06) {
		return true
	}
	if y >= 0.23 && y <= 0.56 {
		t := (y - 0.23) / 0.33
		return math.Abs(x-0.5) <= 0.058-0.02*t
	}
	return false
}

// badge: a dot at the lower right with a transparent gap around it.
const badgeX, badgeY, badgeR, badgeGap = 0.79, 0.79, 0.18, 0.06

// --- tray state painters ---

type state struct {
	name     string
	fill     rgba // shield colour (colour version)
	fill2    rgba // right half shade
	hollow   bool // outline only (idle)
	keyhole  bool
	waves    bool
	exclaim  bool
	badge    bool
	badgeCol rgba
}

var states = []state{
	{name: "idle", fill: grey, fill2: grey, hollow: true, keyhole: true},
	{name: "gateway", fill: blue, fill2: blueDark, waves: true},
	{name: "connected", fill: green, fill2: greenDark, keyhole: true},
	{name: "both", fill: green, fill2: greenDark, keyhole: true, badge: true, badgeCol: blue},
	// Client tunnel interrupted (traffic held) or blocked by the kill switch.
	{name: "warning", fill: amber, fill2: amberDark, exclaim: true},
}

// trayPainter draws a state; template=true draws pure black with alpha
// (macOS tints template images itself).
func trayPainter(s state, template bool) painter {
	return func(x, y float64) rgba {
		if s.badge {
			if inCircle(x, y, badgeX, badgeY, badgeR) {
				if template {
					return black
				}
				return s.badgeCol
			}
			if inCircle(x, y, badgeX, badgeY, badgeR+badgeGap) {
				return transparent
			}
		}
		if !inShield(x, y, 0) {
			return transparent
		}
		col := s.fill
		if !template && x > 0.5 {
			col = s.fill2
		}
		if template {
			col = black
		}
		if s.hollow {
			if inShield(x, y, 0.085) {
				if s.keyhole && inKeyhole(x, y) {
					return col
				}
				return transparent
			}
			return col
		}
		if (s.keyhole && inKeyhole(x, y)) || (s.waves && inWaves(x, y)) || (s.exclaim && inExclaim(x, y)) {
			if template {
				return transparent
			}
			return white
		}
		return col
	}
}

// appPainter is the application icon: the brand shield with a keyhole.
func appPainter(x, y float64) rgba {
	if !inShield(x, y, 0) {
		return transparent
	}
	if inKeyhole(x, y) {
		return white
	}
	if x > 0.5 {
		return blueDark
	}
	return blue
}

// --- rasterising ---

func render(size int, p painter) *image.NRGBA {
	const ss = 4
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var r, g, b, a float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					x := (float64(px) + (float64(sx)+0.5)/ss) / float64(size)
					y := (float64(py) + (float64(sy)+0.5)/ss) / float64(size)
					c := p(x, y)
					r += c.r * c.a
					g += c.g * c.a
					b += c.b * c.a
					a += c.a
				}
			}
			n := float64(ss * ss)
			if a == 0 {
				continue
			}
			img.SetNRGBA(px, py, color.NRGBA{
				R: uint8(math.Round(r / a * 255)),
				G: uint8(math.Round(g / a * 255)),
				B: uint8(math.Round(b / a * 255)),
				A: uint8(math.Round(a / n * 255)),
			})
		}
	}
	return img
}

func pngBytes(img image.Image) []byte {
	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	if err := enc.Encode(&buf, img); err != nil {
		log.Fatal(err)
	}
	return buf.Bytes()
}

// icoBytes writes a Windows .ico. Sizes below 256 are stored as 32-bit
// BMP (DIB) entries for maximum compatibility with LoadImage; 256 as PNG.
func icoBytes(p painter, sizes []int) []byte {
	type entry struct {
		size int
		data []byte
	}
	var entries []entry
	for _, s := range sizes {
		img := render(s, p)
		if s >= 256 {
			entries = append(entries, entry{s, pngBytes(img)})
			continue
		}
		var b bytes.Buffer
		maskStride := ((s + 31) / 32) * 4
		hdr := struct {
			Size, Width, Height int32
			Planes, BitCount    uint16
			Compression, SizeImage,
			XPels, YPels, ClrUsed, ClrImportant uint32
		}{40, int32(s), int32(2 * s), 1, 32, 0, uint32(s*s*4 + maskStride*s), 0, 0, 0, 0}
		binary.Write(&b, binary.LittleEndian, hdr)
		for y := s - 1; y >= 0; y-- { // bottom-up
			for x := 0; x < s; x++ {
				c := img.NRGBAAt(x, y)
				b.Write([]byte{c.B, c.G, c.R, c.A})
			}
		}
		for y := s - 1; y >= 0; y-- { // AND mask: 1 = transparent
			row := make([]byte, maskStride)
			for x := 0; x < s; x++ {
				if img.NRGBAAt(x, y).A == 0 {
					row[x/8] |= 0x80 >> (x % 8)
				}
			}
			b.Write(row)
		}
		entries = append(entries, entry{s, b.Bytes()})
	}
	var out bytes.Buffer
	binary.Write(&out, binary.LittleEndian, [3]uint16{0, 1, uint16(len(entries))})
	offset := 6 + 16*len(entries)
	for _, e := range entries {
		dim := byte(e.size)
		if e.size >= 256 {
			dim = 0
		}
		out.Write([]byte{dim, dim, 0, 0})
		binary.Write(&out, binary.LittleEndian, [2]uint16{1, 32})
		binary.Write(&out, binary.LittleEndian, [2]uint32{uint32(len(e.data)), uint32(offset)})
		offset += len(e.data)
	}
	for _, e := range entries {
		out.Write(e.data)
	}
	return out.Bytes()
}

// icnsBytes writes a macOS .icns with PNG payloads.
func icnsBytes(p painter) []byte {
	types := []struct {
		typ  string
		size int
	}{
		{"icp4", 16}, {"icp5", 32}, {"icp6", 64}, {"ic07", 128}, {"ic08", 256}, {"ic09", 512},
		{"ic10", 1024}, {"ic11", 32}, {"ic12", 64}, {"ic13", 256}, {"ic14", 512},
	}
	cache := map[int][]byte{}
	var body bytes.Buffer
	for _, t := range types {
		data, ok := cache[t.size]
		if !ok {
			data = pngBytes(render(t.size, p))
			cache[t.size] = data
		}
		body.WriteString(t.typ)
		binary.Write(&body, binary.BigEndian, uint32(8+len(data)))
		body.Write(data)
	}
	var out bytes.Buffer
	out.WriteString("icns")
	binary.Write(&out, binary.BigEndian, uint32(8+body.Len()))
	out.Write(body.Bytes())
	return out.Bytes()
}

func write(root, rel string, data []byte) {
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %s (%d bytes)\n", rel, len(data))
}

func main() {
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	if _, err := os.Stat(filepath.Join(*root, "go.mod")); err != nil {
		log.Fatalf("run from the repository root (or pass -root): %v", err)
	}
	for _, s := range states {
		write(*root, "desktop/tray/icons/"+s.name+".png", pngBytes(render(64, trayPainter(s, false))))
		write(*root, "desktop/tray/icons/"+s.name+".ico", icoBytes(trayPainter(s, false), []int{16, 20, 24, 32, 40, 48, 64}))
		write(*root, "desktop/tray/icons/"+s.name+"_template.png", pngBytes(render(32, trayPainter(s, true))))
	}
	write(*root, "build/windows/icon.png", pngBytes(render(256, appPainter)))
	write(*root, "build/windows/icon.ico", icoBytes(appPainter, []int{16, 24, 32, 48, 64, 256}))
	write(*root, "build/linux/icon.png", pngBytes(render(256, appPainter)))
	write(*root, "build/macos/icon.icns", icnsBytes(appPainter))
}
