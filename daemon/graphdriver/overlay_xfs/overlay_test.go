// +build linux
// NOTE: This file is copied from graphdriver/overlay/overlay_test.go and only slightly adapted to make it fit.

package overlay_xfs

import (
	"testing"

	"github.com/docker/docker/daemon/graphdriver"
	"github.com/docker/docker/daemon/graphdriver/graphtest"
	"github.com/docker/docker/pkg/archive"
)

func init() {
	// Do not sure chroot to speed run time and allow archive
	// errors or hangs to be debugged directly from the test process.
	graphdriver.ApplyUncompressedLayer = archive.ApplyUncompressedLayer
}

// This avoids creating a new driver for each test if all tests are run
// Make sure to put new tests between TestOverlaySetup and TestOverlayTeardown
func TestOverlaySetup(t *testing.T) {
	graphtest.GetDriver(t, "overlay_xfs")
}

func TestOverlayCreateEmpty(t *testing.T) {
	graphtest.DriverTestCreateEmpty(t, "overlay_xfs")
}

func TestOverlayCreateBase(t *testing.T) {
	graphtest.DriverTestCreateBase(t, "overlay_xfs")
}

func TestOverlayCreateSnap(t *testing.T) {
	graphtest.DriverTestCreateSnap(t, "overlay_xfs")
}

func TestOverlay50LayerRead(t *testing.T) {
	graphtest.DriverTestDeepLayerRead(t, 50, "overlay_xfs")
}

// Fails due to bug in calculating changes after apply
// likely related to https://github.com/docker/docker/issues/21555
func TestOverlayDiffApply10Files(t *testing.T) {
	t.Skipf("Fails to compute changes after apply intermittently")
	graphtest.DriverTestDiffApply(t, 10, "overlay_xfs")
}

func TestOverlayChanges(t *testing.T) {
	t.Skipf("Fails to compute changes intermittently")
	graphtest.DriverTestChanges(t, "overlay_xfs")
}

func TestOverlayTeardown(t *testing.T) {
	graphtest.PutDriver(t)
}

// Benchmarks should always setup new driver

func BenchmarkExists(b *testing.B) {
	graphtest.DriverBenchExists(b, "overlay_xfs")
}

func BenchmarkGetEmpty(b *testing.B) {
	graphtest.DriverBenchGetEmpty(b, "overlay_xfs")
}

func BenchmarkDiffBase(b *testing.B) {
	graphtest.DriverBenchDiffBase(b, "overlay_xfs")
}

func BenchmarkDiffSmallUpper(b *testing.B) {
	graphtest.DriverBenchDiffN(b, 10, 10, "overlay_xfs")
}

func BenchmarkDiff10KFileUpper(b *testing.B) {
	graphtest.DriverBenchDiffN(b, 10, 10000, "overlay_xfs")
}

func BenchmarkDiff10KFilesBottom(b *testing.B) {
	graphtest.DriverBenchDiffN(b, 10000, 10, "overlay_xfs")
}

func BenchmarkDiffApply100(b *testing.B) {
	graphtest.DriverBenchDiffApplyN(b, 100, "overlay_xfs")
}

func BenchmarkDiff20Layers(b *testing.B) {
	graphtest.DriverBenchDeepLayerDiff(b, 20, "overlay_xfs")
}

func BenchmarkRead20Layers(b *testing.B) {
	graphtest.DriverBenchDeepLayerRead(b, 20, "overlay_xfs")
}
