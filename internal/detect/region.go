package detect

import (
	"context"
	"image"
	"image/color"
)

// RegionMarkerDetector finds axis-aligned rectangular regions painted in a
// configured marker color. It is deterministic and stdlib-only, intended for
// explicit-zone redaction ("paint the area to hide in magenta") and for the
// demo and tests. It reports one Region per connected blob of marker-colored
// pixels, using that blob's bounding box.
type RegionMarkerDetector struct {
	// Marker is the color to look for.
	Marker color.RGBA
	// Tolerance is the maximum per-channel absolute difference (0-255) for a
	// pixel to count as the marker color. 0 means exact match.
	Tolerance uint32
	// MinArea ignores blobs whose bounding-box area is below this value
	// (noise suppression). 0 keeps every blob with at least one pixel.
	MinArea int
	// Category labels the produced regions in the audit log. Defaults to
	// "marker" when empty.
	Category string
}

// Name implements Detector.
func (d *RegionMarkerDetector) Name() string { return "region-marker" }

// Detect implements Detector. It scans every pixel once, groups
// marker-colored pixels into connected components (4-connectivity) via a
// union-find over the pixel grid, and returns each component's bounding box.
// The returned regions are ordered deterministically by (MinY, MinX).
func (d *RegionMarkerDetector) Detect(ctx context.Context, img image.Image) ([]Region, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if w <= 0 || h <= 0 {
		return nil, nil
	}

	category := d.Category
	if category == "" {
		category = "marker"
	}

	// match[y*w+x] is true when the pixel is marker-colored.
	match := make([]bool, w*h)
	any := false
	for y := 0; y < h; y++ {
		if y%64 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		for x := 0; x < w; x++ {
			if d.matches(img.At(b.Min.X+x, b.Min.Y+y)) {
				match[y*w+x] = true
				any = true
			}
		}
	}
	if !any {
		return nil, nil
	}

	uf := newUnionFind(w * h)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			i := y*w + x
			if !match[i] {
				continue
			}
			if x+1 < w && match[i+1] {
				uf.union(i, i+1)
			}
			if y+1 < h && match[i+w] {
				uf.union(i, i+w)
			}
		}
	}

	// Accumulate bounding box per component root.
	type box struct{ minX, minY, maxX, maxY int }
	boxes := make(map[int]*box)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			i := y*w + x
			if !match[i] {
				continue
			}
			r := uf.find(i)
			bx := boxes[r]
			if bx == nil {
				boxes[r] = &box{minX: x, minY: y, maxX: x, maxY: y}
				continue
			}
			if x < bx.minX {
				bx.minX = x
			}
			if x > bx.maxX {
				bx.maxX = x
			}
			if y < bx.minY {
				bx.minY = y
			}
			if y > bx.maxY {
				bx.maxY = y
			}
		}
	}

	regions := make([]Region, 0, len(boxes))
	for _, bx := range boxes {
		// Convert inclusive pixel bounds to a half-open rectangle in image
		// coordinates.
		rect := image.Rect(
			b.Min.X+bx.minX, b.Min.Y+bx.minY,
			b.Min.X+bx.maxX+1, b.Min.Y+bx.maxY+1,
		)
		if d.MinArea > 0 && rect.Dx()*rect.Dy() < d.MinArea {
			continue
		}
		regions = append(regions, Region{Rect: rect, Category: category, Confidence: 1})
	}

	sortRegions(regions)
	return regions, nil
}

func (d *RegionMarkerDetector) matches(c color.Color) bool {
	r, g, b, a := c.RGBA() // 16-bit pre-multiplied values in [0,65535].
	// Convert to 8-bit.
	r8, g8, b8, a8 := r>>8, g>>8, b>>8, a>>8
	if absDiff(a8, uint32(d.Marker.A)) > d.Tolerance {
		return false
	}
	return absDiff(r8, uint32(d.Marker.R)) <= d.Tolerance &&
		absDiff(g8, uint32(d.Marker.G)) <= d.Tolerance &&
		absDiff(b8, uint32(d.Marker.B)) <= d.Tolerance
}

func absDiff(a, b uint32) uint32 {
	if a > b {
		return a - b
	}
	return b - a
}

// unionFind is a tiny disjoint-set with path compression and union by rank.
type unionFind struct {
	parent []int
	rank   []int
}

func newUnionFind(n int) *unionFind {
	uf := &unionFind{parent: make([]int, n), rank: make([]int, n)}
	for i := range uf.parent {
		uf.parent[i] = i
	}
	return uf
}

func (uf *unionFind) find(i int) int {
	for uf.parent[i] != i {
		uf.parent[i] = uf.parent[uf.parent[i]]
		i = uf.parent[i]
	}
	return i
}

func (uf *unionFind) union(a, b int) {
	ra, rb := uf.find(a), uf.find(b)
	if ra == rb {
		return
	}
	if uf.rank[ra] < uf.rank[rb] {
		ra, rb = rb, ra
	}
	uf.parent[rb] = ra
	if uf.rank[ra] == uf.rank[rb] {
		uf.rank[ra]++
	}
}
