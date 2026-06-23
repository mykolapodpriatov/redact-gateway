package imageproc

import (
	"image"
	"image/color"
	"image/draw"
)

// MaskMode selects how a region is obscured.
type MaskMode int

const (
	// MaskSolid paints the region with a single opaque color (default black).
	MaskSolid MaskMode = iota
	// MaskBlur replaces the region with a bounded separable box blur of its
	// own pixels, destroying fine detail while keeping rough structure.
	MaskBlur
)

// MaskOptions configures Mask.
type MaskOptions struct {
	// Mode is solid or blur.
	Mode MaskMode
	// Fill is the solid color used when Mode == MaskSolid. The zero value is
	// transparent; Mask substitutes opaque black for a zero-alpha fill so a
	// "redact" never accidentally leaves the region see-through.
	Fill color.Color
	// BlurRadius is the box-blur radius in pixels when Mode == MaskBlur. Values
	// <= 0 are treated as 1. The radius is internally clamped so it never
	// exceeds the region size.
	BlurRadius int
}

// Mask returns a new RGBA image equal to src with every region in regions
// obscured according to opts. The input image is never mutated. Each region
// rectangle is intersected with the image bounds, so out-of-range or
// negative-area rectangles are safely ignored. Masking is idempotent and
// order-independent for solid fills, so overlapping regions are fine.
func Mask(src image.Image, regions []image.Rectangle, opts MaskOptions) *image.RGBA {
	b := src.Bounds()
	out := image.NewRGBA(b)
	draw.Draw(out, b, src, b.Min, draw.Src)

	for _, r := range regions {
		clipped := r.Intersect(b)
		if clipped.Empty() {
			continue
		}
		switch opts.Mode {
		case MaskBlur:
			blurRegion(out, clipped, opts.BlurRadius)
		default:
			fill := opts.Fill
			if fill == nil || isTransparent(fill) {
				fill = color.RGBA{R: 0, G: 0, B: 0, A: 255}
			}
			draw.Draw(out, clipped, image.NewUniform(fill), image.Point{}, draw.Src)
		}
	}
	return out
}

func isTransparent(c color.Color) bool {
	_, _, _, a := c.RGBA()
	return a == 0
}

// blurRegion applies a separable box blur of the given radius to the pixels of
// rect within img, reading from a snapshot so the blur samples original pixels
// (not partially-blurred ones). The radius is clamped to the region size.
func blurRegion(img *image.RGBA, rect image.Rectangle, radius int) {
	if radius <= 0 {
		radius = 1
	}
	w, h := rect.Dx(), rect.Dy()
	if w <= 0 || h <= 0 {
		return
	}
	// Clamp radius so the kernel never exceeds the region extent.
	if radius > w {
		radius = w
	}
	if radius > h {
		radius = h
	}

	// Snapshot the region's RGBA values into local slices indexed [y][x].
	type px struct{ r, g, b, a uint32 }
	src := make([]px, w*h)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			c := img.RGBAAt(rect.Min.X+x, rect.Min.Y+y)
			src[y*w+x] = px{uint32(c.R), uint32(c.G), uint32(c.B), uint32(c.A)}
		}
	}

	// Horizontal pass into tmp.
	tmp := make([]px, w*h)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			var sr, sg, sb, sa, n uint32
			for dx := -radius; dx <= radius; dx++ {
				xx := x + dx
				if xx < 0 || xx >= w {
					continue
				}
				p := src[y*w+xx]
				sr += p.r
				sg += p.g
				sb += p.b
				sa += p.a
				n++
			}
			tmp[y*w+x] = px{sr / n, sg / n, sb / n, sa / n}
		}
	}

	// Vertical pass into dst, then write back to the image.
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			var sr, sg, sb, sa, n uint32
			for dy := -radius; dy <= radius; dy++ {
				yy := y + dy
				if yy < 0 || yy >= h {
					continue
				}
				p := tmp[yy*w+x]
				sr += p.r
				sg += p.g
				sb += p.b
				sa += p.a
				n++
			}
			img.SetRGBA(rect.Min.X+x, rect.Min.Y+y, color.RGBA{
				R: uint8(sr / n),
				G: uint8(sg / n),
				B: uint8(sb / n),
				A: uint8(sa / n),
			})
		}
	}
}
