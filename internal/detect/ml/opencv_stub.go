//go:build opencv

// This file is compiled ONLY with `-tags opencv`; it is excluded from the
// default build and from CI. It is a scaffold showing how an OpenCV-backed
// face detector would plug into the pipeline via the detect.Detector
// interface. It deliberately does not import gocv so the repository stays
// dependency-free; a real implementation would replace the body with gocv
// Haar-cascade or DNN face detection.

package ml

import (
	"context"
	"errors"
	"image"

	"redact-gateway/internal/detect"
)

// ErrNotImplemented is returned by the scaffold adapter. A real opencv build
// would replace this with working detection.
var ErrNotImplemented = errors.New("ml: opencv face detector not implemented in scaffold")

// FaceDetector is the optional OpenCV-backed face detector. With -tags opencv
// it satisfies detect.Detector; the default build never compiles it.
type FaceDetector struct {
	// CascadePath would point to a Haar cascade XML in a real implementation.
	CascadePath string
}

// Name implements detect.Detector.
func (d *FaceDetector) Name() string { return "face" }

// Detect implements detect.Detector. The scaffold returns ErrNotImplemented so
// the fail-closed pipeline blocks rather than silently passing unredacted
// faces; a real adapter returns face regions.
func (d *FaceDetector) Detect(_ context.Context, _ image.Image) ([]detect.Region, error) {
	return nil, ErrNotImplemented
}
