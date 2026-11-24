// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"crypto/fips140"
	"crypto/pbkdf2"
	"errors"
	"fmt"
	"hash"
	"math"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/jeremyhahn/go-luks2/internal/fips"
	"github.com/jeremyhahn/go-luks2/internal/header"

	"golang.org/x/sys/unix"
)

// Calibration tests inject a known hash rate and assert exact counts; real-work checks are benchmarks run by make test-calibration.

// knownRate is a pbkdf2Timer for a machine that derives at exactly
// perIteration, whatever else it is doing. It records the output size and the
// hash width of every derivation it was asked to time.
type knownRate struct {
	perIteration time.Duration
	probes       []int
	keySizes     []int
	hashWidths   []int
}

func (r *knownRate) time(hashFunc func() hash.Hash, iterations, keySize int) (time.Duration, error) {
	r.probes = append(r.probes, iterations)
	r.keySizes = append(r.keySizes, keySize)
	r.hashWidths = append(r.hashWidths, hashFunc().Size())
	return time.Duration(iterations) * r.perIteration, nil
}

// threadCPUPBKDF2 is a pbkdf2Timer that runs the real derivation and times it
// in the CPU time of the thread that ran it. Time the scheduler gives to other
// work is not counted; cache and frequency effects still are.
func threadCPUPBKDF2(hashFunc func() hash.Hash, iterations, keySize int) (time.Duration, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var start, end unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &start); err != nil {
		return 0, err
	}
	if _, err := pbkdf2.Key(hashFunc, "timing-probe-passphrase", make([]byte, 32), iterations, keySize); err != nil {
		return 0, err
	}
	if err := unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &end); err != nil {
		return 0, err
	}
	return time.Duration(end.Nano() - start.Nano()), nil
}

// checkCalibrationCost calibrates and derives with the real hash in thread CPU time and requires the count within 4x of the target, after clamping.
func checkCalibrationCost(b *testing.B, hashAlgo string, keySize, targetMs int, calibrate func(pbkdf2Timer) (int, error)) {
	b.Helper()
	iterations, err := calibrate(threadCPUPBKDF2)
	if err != nil {
		b.Fatalf("calibrating %s: %v", hashAlgo, err)
	}
	hashFunc, err := getPBKDF2HashFunc(hashAlgo, fips.Probe)
	if err != nil {
		b.Fatalf("getPBKDF2HashFunc(%q): %v", hashAlgo, err)
	}
	cost, err := threadCPUPBKDF2(hashFunc, iterations, keySize)
	if err != nil {
		b.Fatalf("timing the calibrated derivation: %v", err)
	}
	target := time.Duration(targetMs) * time.Millisecond
	perIteration := float64(cost) / float64(iterations)
	want := math.Max(pbkdf2IterationFloor(hashAlgo, targetMs), float64(target)/perIteration)
	want = math.Min(want, header.MaxKDFIterations)
	if got := float64(iterations); got < want/4 || got > want*4 {
		b.Errorf("calibrated to %d %s iterations; the derivation's own CPU rate (%v per iteration) puts the %v target at %.0f",
			iterations, hashAlgo, time.Duration(perIteration), target, want)
	}
}

// TestBenchmarkPBKDF2CalibratesToRequestedTime: at an injected rate the count is exactly what the budget buys, including sub-millisecond probes.
func TestBenchmarkPBKDF2CalibratesToRequestedTime(t *testing.T) {
	for _, tc := range []struct {
		hashAlgo     string
		keySize      int
		targetMs     int
		perIteration time.Duration
	}{
		{"sha256", 32, 3000, time.Microsecond},
		{"sha512", 64, 3000, 2 * time.Microsecond},
		{"sha256", 32, 2000, 360 * time.Nanosecond},
		{"sha512", 64, 500, 900 * time.Nanosecond},
	} {
		t.Run(fmt.Sprintf("%s %dms at %v", tc.hashAlgo, tc.targetMs, tc.perIteration), func(t *testing.T) {
			hashFunc, err := getPBKDF2HashFunc(tc.hashAlgo, fips.Probe)
			if err != nil {
				t.Fatalf("getPBKDF2HashFunc: %v", err)
			}
			rate := &knownRate{perIteration: tc.perIteration}
			iterations, err := calibratePBKDF2(hashFunc, tc.hashAlgo, tc.keySize, tc.targetMs,
				pbkdf2ProbeFloor, pbkdf2ProbeCeiling, rate.time)
			if err != nil {
				t.Fatalf("calibratePBKDF2: %v", err)
			}

			want := int(time.Duration(tc.targetMs) * time.Millisecond / tc.perIteration)
			if float64(want) < pbkdf2IterationFloor(tc.hashAlgo, tc.targetMs) {
				t.Fatalf("fixture error: the %v case lands under the floor and would not test the extrapolation", tc.perIteration)
			}
			if iterations < want-1 || iterations > want+1 {
				t.Fatalf("calibrated to %d iterations; at %v per iteration the %dms target is %d",
					iterations, tc.perIteration, tc.targetMs, want)
			}
			for i, size := range rate.keySizes {
				if size != tc.keySize {
					t.Fatalf("probe %d derived %d bytes, want the %d being calibrated for", i, size, tc.keySize)
				}
			}
		})
	}
}

// TestBenchmarkPBKDF2ScalesWithRequestedTime: twenty times the budget buys twenty times the iterations.
func TestBenchmarkPBKDF2ScalesWithRequestedTime(t *testing.T) {
	defer parallel(t)()

	const (
		shortMs = 100
		longMs  = 2000
	)
	hashFunc, err := getPBKDF2HashFunc("sha256", fips.Probe)
	if err != nil {
		t.Fatalf("getPBKDF2HashFunc: %v", err)
	}
	calibrate := func(targetMs int) int {
		t.Helper()
		rate := &knownRate{perIteration: 500 * time.Nanosecond}
		n, err := calibratePBKDF2(hashFunc, "sha256", 32, targetMs, pbkdf2ProbeFloor, pbkdf2ProbeCeiling, rate.time)
		if err != nil {
			t.Fatalf("calibratePBKDF2 at %dms: %v", targetMs, err)
		}
		return n
	}

	short, long := calibrate(shortMs), calibrate(longMs)
	// 200,000 and 4,000,000 at 500ns per iteration, each within one iteration
	// of float rounding.
	if short < 199_999 || short > 200_001 || long < 3_999_999 || long > 4_000_001 {
		t.Fatalf("%dms gave %d and %dms gave %d; at 500ns per iteration want 200000 and 4000000",
			shortMs, short, longMs, long)
	}
}

// TestBenchmarkPBKDF2MeetsRecommendedMinimum: at the default budget the count is at least the OWASP recommendation. make test-calibration runs without -race, because -race hides the slow-probe defect.
func TestBenchmarkPBKDF2MeetsRecommendedMinimum(t *testing.T) {
	defer parallel(t)()

	tests := []struct {
		name     string
		hashAlgo string
		keySize  int
	}{
		{"sha256", "sha256", 32},
		{"sha384", "sha384", 48},
		{"sha512", "sha512", 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iterations, err := benchmarkPBKDF2(defaultVolumeSys().fipsMode(), tt.hashAlgo, tt.keySize, pbkdf2ReferenceTargetMs)
			if err != nil {
				t.Fatalf("BenchmarkPBKDF2(%q, %d, %d): %v", tt.hashAlgo, tt.keySize, pbkdf2ReferenceTargetMs, err)
			}

			want := pbkdf2RecommendedIterations[tt.hashAlgo]
			t.Logf("%s at %dms: %d iterations (recommended minimum %d)", tt.hashAlgo, pbkdf2ReferenceTargetMs, iterations, want)

			if iterations < want {
				t.Fatalf("%s at the %dms default: got %d iterations, want at least the recommended %d",
					tt.hashAlgo, pbkdf2ReferenceTargetMs, iterations, want)
			}
			if iterations > header.MaxKDFIterations {
				t.Fatalf("%s: got %d iterations, above the %d ceiling header.ValidateKDFCost enforces on read-back",
					tt.hashAlgo, iterations, header.MaxKDFIterations)
			}
		})
	}
}

// TestBenchmarkPBKDF2RejectsUnusableTarget pins the fail-closed contract on the
// request. A budget that is not a usable number of milliseconds produces a
// typed error and NO count -- never a quietly weakened default.
func TestBenchmarkPBKDF2RejectsUnusableTarget(t *testing.T) {
	tests := []struct {
		name     string
		targetMs int
	}{
		{"zero", 0},
		{"negative", -1},
		{"past the supported range", maxPBKDF2IterTimeMs + 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iterations, err := benchmarkPBKDF2(defaultVolumeSys().fipsMode(), "sha256", 32, tt.targetMs)
			if err == nil {
				t.Fatalf("BenchmarkPBKDF2 with a target of %dms returned %d iterations and no error", tt.targetMs, iterations)
			}
			if iterations != 0 {
				t.Fatalf("BenchmarkPBKDF2 with a target of %dms returned %d iterations alongside its error; a refused calibration returns no count",
					tt.targetMs, iterations)
			}
			if !errors.Is(err, ErrKDFCalibration) {
				t.Fatalf("got error %v, want one matching ErrKDFCalibration", err)
			}
			if !errors.Is(err, errCalibrationTargetInvalid) {
				t.Fatalf("got error %v, want one matching errCalibrationTargetInvalid", err)
			}

			var calErr *KDFCalibrationError
			if !errors.As(err, &calErr) {
				t.Fatalf("got error %v, want a *KDFCalibrationError", err)
			}
			if calErr.TargetMs != tt.targetMs {
				t.Fatalf("error carries target %dms, want %dms", calErr.TargetMs, tt.targetMs)
			}
		})
	}
}

// TestCalibratePBKDF2FailsClosedWhenUnmeasurable: no probe up to the ceiling is timeable, so calibration fails.
func TestCalibratePBKDF2FailsClosedWhenUnmeasurable(t *testing.T) {
	hashFunc, err := getPBKDF2HashFunc("sha256", fips.Probe)
	if err != nil {
		t.Fatalf("getPBKDF2HashFunc: %v", err)
	}

	rate := &knownRate{perIteration: time.Microsecond}
	iterations, err := calibratePBKDF2(hashFunc, "sha256", 32, 2000, time.Hour, pbkdf2ProbeStart, rate.time)
	if err == nil {
		t.Fatalf("an immeasurable calibration returned %d iterations and no error", iterations)
	}
	if iterations != 0 {
		t.Fatalf("an immeasurable calibration returned %d iterations alongside its error", iterations)
	}
	if !errors.Is(err, ErrKDFCalibration) {
		t.Fatalf("got error %v, want one matching ErrKDFCalibration", err)
	}
	if !errors.Is(err, errCalibrationImmeasurable) {
		t.Fatalf("got error %v, want one matching errCalibrationImmeasurable", err)
	}

	var calErr *KDFCalibrationError
	if !errors.As(err, &calErr) {
		t.Fatalf("got error %v, want a *KDFCalibrationError", err)
	}
	if calErr.Probe != pbkdf2ProbeStart {
		t.Fatalf("error reports probe %d, want the %d that was run", calErr.Probe, pbkdf2ProbeStart)
	}
	// The probe did run, and its measurement is what could not be used: the
	// error carries exactly what was measured.
	if want := pbkdf2ProbeStart * time.Microsecond; calErr.Elapsed != want {
		t.Fatalf("error reports elapsed %v, want the probe's measured %v", calErr.Elapsed, want)
	}
}

// TestCalibratePBKDF2StopsDoublingAtTheCeiling: the ceiling bounds the work, not just the loop.
func TestCalibratePBKDF2StopsDoublingAtTheCeiling(t *testing.T) {
	hashFunc, err := getPBKDF2HashFunc("sha256", fips.Probe)
	if err != nil {
		t.Fatalf("getPBKDF2HashFunc: %v", err)
	}

	// A ceiling of 4000 admits probes of 1000, 2000 and 4000 and then refuses:
	// 4000 is not <= 4000/2. The largest probe RUN is the ceiling itself, never
	// a doubling past it.
	const ceiling = 4 * pbkdf2ProbeStart

	rate := &knownRate{perIteration: time.Microsecond}
	_, err = calibratePBKDF2(hashFunc, "sha256", 32, 2000, time.Hour, ceiling, rate.time)
	var calErr *KDFCalibrationError
	if !errors.As(err, &calErr) {
		t.Fatalf("got error %v, want a *KDFCalibrationError", err)
	}

	// This also pins the doubling: a fixed probe would report pbkdf2ProbeStart.
	if calErr.Probe == pbkdf2ProbeStart {
		t.Fatalf("the probe never grew past its starting size of %d; the calibration is not scaling the probe to the machine", pbkdf2ProbeStart)
	}
	if calErr.Probe != ceiling {
		t.Fatalf("largest probe run was %d, want the ceiling %d", calErr.Probe, ceiling)
	}
	if want := []int{pbkdf2ProbeStart, 2 * pbkdf2ProbeStart, 4 * pbkdf2ProbeStart}; !slices.Equal(rate.probes, want) {
		t.Fatalf("probes run: %v, want %v -- doubling, and stopping at the ceiling", rate.probes, want)
	}
}

// BenchmarkPBKDF2CalibrationCostsItsBudget is the real-work keyslot calibration check, run by make test-calibration; see checkCalibrationCost.
func BenchmarkPBKDF2CalibrationCostsItsBudget(b *testing.B) {
	const targetMs = 500
	for _, tc := range []struct {
		hashAlgo string
		keySize  int
	}{{"sha256", 32}, {"sha512", 64}} {
		b.Run(tc.hashAlgo, func(b *testing.B) {
			hashFunc, err := getPBKDF2HashFunc(tc.hashAlgo, fips.Probe)
			if err != nil {
				b.Fatalf("getPBKDF2HashFunc: %v", err)
			}
			for b.Loop() {
				checkCalibrationCost(b, tc.hashAlgo, tc.keySize, targetMs, func(timer pbkdf2Timer) (int, error) {
					return calibratePBKDF2(hashFunc, tc.hashAlgo, tc.keySize, targetMs, pbkdf2ProbeFloor, pbkdf2ProbeCeiling, timer)
				})
			}
		})
	}
}

// TestPBKDF2IterationFloor covers the floor on its own, including the two
// arguments the crypto-driven tests cannot reach: sha1, which is refused
// outright in FIPS mode, and a hash with no recommendation at all.
func TestPBKDF2IterationFloor(t *testing.T) {
	tests := []struct {
		name     string
		hashAlgo string
		targetMs int
		want     float64
	}{
		{"sha256 at the reference budget", "sha256", pbkdf2ReferenceTargetMs, 600_000},
		{"sha512 at the reference budget", "sha512", pbkdf2ReferenceTargetMs, 210_000},
		{"sha384 at the reference budget", "sha384", pbkdf2ReferenceTargetMs, 210_000},
		{"sha1 at the reference budget", "sha1", pbkdf2ReferenceTargetMs, 1_300_000},
		{"case is normalized", "SHA256", pbkdf2ReferenceTargetMs, 600_000},
		{"the floor scales with the budget", "sha256", pbkdf2ReferenceTargetMs / 4, 150_000},
		{"a cheap budget falls back to the absolute minimum", "sha256", 1, minPBKDF2Iterations},
		{"an unrecommended hash gets the absolute minimum", "sha3-512", pbkdf2ReferenceTargetMs, minPBKDF2Iterations},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pbkdf2IterationFloor(tt.hashAlgo, tt.targetMs); got != tt.want {
				t.Fatalf("pbkdf2IterationFloor(%q, %d) = %v, want %v", tt.hashAlgo, tt.targetMs, got, tt.want)
			}
		})
	}
}

// TestScalePBKDF2IterationsClamps drives the extrapolation directly with
// fabricated probe measurements, so the two clamps can be reached without
// hardware that is absurdly fast or absurdly slow.
func TestScalePBKDF2IterationsClamps(t *testing.T) {
	tests := []struct {
		name     string
		hashAlgo string
		probe    int
		elapsed  time.Duration
		targetMs int
		want     int
	}{
		{
			// 1000 iterations in 100ms is 10 iterations per millisecond, so a
			// 2000ms budget extrapolates to 20000 -- below the 600000 floor.
			name:     "a slow machine is raised to the security floor",
			hashAlgo: "sha256", probe: 1000, elapsed: 100 * time.Millisecond,
			targetMs: pbkdf2ReferenceTargetMs, want: 600_000,
		},
		{
			// 1000000 iterations in 1ms extrapolates to 2e12, far past the
			// ceiling header.ValidateKDFCost applies on read-back.
			name:     "an implausibly fast machine is capped at the header ceiling",
			hashAlgo: "sha256", probe: 1_000_000, elapsed: time.Millisecond,
			targetMs: pbkdf2ReferenceTargetMs, want: header.MaxKDFIterations,
		},
		{
			// A budget whose floor alone exceeds the ceiling must land ON the
			// ceiling: the floor is applied first and the ceiling second.
			name:     "the ceiling wins over a floor that exceeds it",
			hashAlgo: "sha1", probe: 1000, elapsed: time.Second,
			targetMs: maxPBKDF2IterTimeMs, want: header.MaxKDFIterations,
		},
		{
			name:     "a measurement between the two is used as measured",
			hashAlgo: "sha256", probe: 100_000, elapsed: 50 * time.Millisecond,
			targetMs: pbkdf2ReferenceTargetMs, want: 4_000_000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scalePBKDF2Iterations(tt.hashAlgo, tt.probe, tt.elapsed, tt.targetMs)
			if got != tt.want {
				t.Fatalf("scalePBKDF2Iterations(%q, %d, %v, %d) = %d, want %d",
					tt.hashAlgo, tt.probe, tt.elapsed, tt.targetMs, got, tt.want)
			}
			if got < minPBKDF2Iterations {
				t.Fatalf("got %d iterations, below the absolute minimum %d", got, minPBKDF2Iterations)
			}
		})
	}
}

// TestCreateKDFPBKDF2CalibratesTheKeyslot: the count CreateKDF writes into the keyslot is the calibrated one.
func TestCreateKDFPBKDF2CalibratesTheKeyslot(t *testing.T) {
	defer parallel(t)()

	kdf, err := createKDFStrictAtProductionFloor(formatOptionsForTest{KDFType: kdfTypePBKDF2SHA256}, 32)
	if err != nil {
		t.Fatalf("CreateKDF: %v", err)
	}
	if kdf.Iterations == nil {
		t.Fatal("CreateKDF produced a pbkdf2 KDF with no iteration count")
	}

	// createPBKDF2KDF defaults an unset PBKDFIterTime to the reference budget,
	// so the recommended minimum for sha256 applies in full.
	want := pbkdf2RecommendedIterations["sha256"]
	t.Logf("default pbkdf2-sha256 keyslot: %d iterations", *kdf.Iterations)

	if *kdf.Iterations < want {
		t.Fatalf("default keyslot got %d iterations, want at least the recommended %d -- the count written to the header is not calibrated",
			*kdf.Iterations, want)
	}

	// A count outside the read-back bounds would produce a keyslot this package
	// refuses to open, which is the other way a wrong count breaks a volume.
	if err := header.ValidateKDFCost(kdf); err != nil {
		t.Fatalf("the KDF CreateKDF produced does not pass its own read-back validation: %v", err)
	}
}

// TestCreateKDFPBKDF2RejectsUnusableIterTime pins that the refusal propagates:
// an unusable PBKDFIterTime fails the format rather than silently producing a
// keyslot with some other cost.
func TestCreateKDFPBKDF2RejectsUnusableIterTime(t *testing.T) {
	kdf, err := createKDFStrict(formatOptionsForTest{KDFType: kdfTypePBKDF2SHA256, PBKDFIterTime: -1}, 32)
	if err == nil {
		t.Fatalf("CreateKDF with a negative PBKDFIterTime produced a keyslot with %v iterations", kdf.Iterations)
	}
	if !errors.Is(err, ErrKDFCalibration) {
		t.Fatalf("got error %v, want one matching ErrKDFCalibration", err)
	}
}

// TestAddKeyFormatOptionsPropagatesTheIterTime: an unusable PBKDFIterTime is refused through every API.
func TestAddKeyFormatOptionsPropagatesTheIterTime(t *testing.T) {
	tests := []struct {
		name string
		opts *addKeyOptionsForTest
		want int
	}{
		{"nil options leave it unset", nil, 0},
		{"unset stays unset so the default applies", &addKeyOptionsForTest{KDFType: kdfTypePBKDF2}, 0},
		{"a usable budget is carried", &addKeyOptionsForTest{KDFType: kdfTypePBKDF2, PBKDFIterTime: 500}, 500},
		{"a negative budget is carried, not dropped", &addKeyOptionsForTest{KDFType: kdfTypePBKDF2, PBKDFIterTime: -1}, -1},
		{"an out-of-range budget is carried, not dropped", &addKeyOptionsForTest{KDFType: kdfTypePBKDF2, PBKDFIterTime: maxPBKDF2IterTimeMs + 1}, maxPBKDF2IterTimeMs + 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := baseAddKeyFormatOptions(tt.opts).PBKDFIterTime; got != tt.want {
				t.Fatalf("baseAddKeyFormatOptions(%+v).PBKDFIterTime = %d, want %d", tt.opts, got, tt.want)
			}
		})
	}
}

// TestAddKeyFormatOptionsRefusesAnUnusableIterTime closes the loop: the mapped
// options are handed to CreateKDF, and that is where the refusal has to land.
// Asserting the field alone would pin the plumbing without pinning the outcome.
func TestAddKeyFormatOptionsRefusesAnUnusableIterTime(t *testing.T) {
	opts := baseAddKeyFormatOptions(&addKeyOptionsForTest{KDFType: kdfTypePBKDF2, PBKDFIterTime: -1})

	kdf, err := createKDFStrict(opts, 32)
	if err == nil {
		t.Fatalf("CreateKDF accepted a negative PBKDFIterTime through AddKeyOptions and produced %v iterations", kdf.Iterations)
	}
	if !errors.Is(err, ErrKDFCalibration) {
		t.Fatalf("got error %v, want one matching ErrKDFCalibration", err)
	}
}

// TestAddKeyFormatOptionsKeepsItsDefaults guards the rest of the mapping, which
// moved out of AddKey in the same change. A refactor that silently dropped the
// Argon2 defaults would leave CreateKDF deriving with zero cost.
func TestAddKeyFormatOptionsKeepsItsDefaults(t *testing.T) {
	got := baseAddKeyFormatOptions(nil)

	// The KDF is the mode's default, and the hash is the one it names.
	wantKDF, wantHash := kdfTypeArgon2id, defaultHashAlgo
	if fips140.Enabled() {
		wantKDF, wantHash = kdfTypePBKDF2SHA512, "sha512"
	}
	if got.KDFType != wantKDF {
		t.Fatalf("default KDFType = %q, want %q", got.KDFType, wantKDF)
	}
	if got.HashAlgo != wantHash {
		t.Fatalf("default HashAlgo = %q, want %q", got.HashAlgo, wantHash)
	}
	if got.Argon2Time != 4 || got.Argon2Memory != 1048576 || got.Argon2Parallel != 4 {
		t.Fatalf("default Argon2 costs = time %d, memory %d, parallel %d; want 4, 1048576, 4",
			got.Argon2Time, got.Argon2Memory, got.Argon2Parallel)
	}

	// An explicit choice overrides each default.
	custom := baseAddKeyFormatOptions(&addKeyOptionsForTest{
		KDFType: kdfTypePBKDF2SHA512, Hash: "sha512",
		Argon2Time: 8, Argon2Memory: 2048, Argon2Parallel: 2,
	})
	if custom.KDFType != kdfTypePBKDF2SHA512 || custom.HashAlgo != "sha512" ||
		custom.Argon2Time != 8 || custom.Argon2Memory != 2048 || custom.Argon2Parallel != 2 {
		t.Fatalf("explicit options were not carried through: %+v", custom)
	}
}
