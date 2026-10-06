// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package kdf

import (
	"errors"
	"hash"
	"testing"
	"time"
)

// knownRate models a timer whose cost per iteration is fixed, so calibration
// math can be checked without running real derivations.
type knownRate struct {
	perIteration time.Duration
}

func (r *knownRate) time(hashFunc func() hash.Hash, iterations, keySize int) (time.Duration, error) {
	return time.Duration(iterations) * r.perIteration, nil
}

func TestCalibratePBKDF2CalibratesToRequestedTime(t *testing.T) {
	hashFunc, err := PBKDF2HashFunc(testDeriver.FIPS, "sha256")
	if err != nil {
		t.Fatalf("PBKDF2HashFunc: %v", err)
	}
	rate := &knownRate{perIteration: time.Microsecond}
	const targetMs = 3000
	iterations, err := CalibratePBKDF2(hashFunc, "sha256", 32, targetMs, ProbeFloor, ProbeCeiling, rate.time)
	if err != nil {
		t.Fatalf("CalibratePBKDF2: %v", err)
	}
	want := int(time.Duration(targetMs) * time.Millisecond / rate.perIteration)
	if iterations < want-1 || iterations > want+1 {
		t.Fatalf("calibrated to %d iterations; at %v per iteration the %dms target is %d", iterations, rate.perIteration, targetMs, want)
	}
}

func TestCalibratePBKDF2RejectsAnUnusableTarget(t *testing.T) {
	hashFunc, err := PBKDF2HashFunc(testDeriver.FIPS, "sha256")
	if err != nil {
		t.Fatalf("PBKDF2HashFunc: %v", err)
	}
	for _, targetMs := range []int{0, -1, MaxPBKDF2IterTimeMs + 1} {
		_, err := CalibratePBKDF2(hashFunc, "sha256", 32, targetMs, ProbeFloor, ProbeCeiling, WallClockPBKDF2)
		if !errors.Is(err, ErrKDFCalibration) || !errors.Is(err, ErrCalibrationTargetInvalid) {
			t.Fatalf("targetMs %d: got %v, want ErrKDFCalibration and ErrCalibrationTargetInvalid", targetMs, err)
		}
		var calErr *CalibrationError
		if !errors.As(err, &calErr) || calErr.TargetMs != targetMs {
			t.Fatalf("targetMs %d: got %v, want a *CalibrationError carrying it", targetMs, err)
		}
	}
}

func TestCalibratePBKDF2FailsClosedWhenUnmeasurable(t *testing.T) {
	hashFunc, err := PBKDF2HashFunc(testDeriver.FIPS, "sha256")
	if err != nil {
		t.Fatalf("PBKDF2HashFunc: %v", err)
	}
	rate := &knownRate{perIteration: time.Microsecond}
	_, err = CalibratePBKDF2(hashFunc, "sha256", 32, 2000, time.Hour, ProbeStart, rate.time)
	if err == nil {
		t.Fatal("a probe floor no real duration can cross was accepted")
	}
	if !errors.Is(err, ErrCalibrationImmeasurable) {
		t.Fatalf("got %v, want ErrCalibrationImmeasurable", err)
	}
}

func TestCalibratePBKDF2StopsDoublingAtTheCeiling(t *testing.T) {
	hashFunc, err := PBKDF2HashFunc(testDeriver.FIPS, "sha256")
	if err != nil {
		t.Fatalf("PBKDF2HashFunc: %v", err)
	}
	rate := &knownRate{perIteration: time.Microsecond}
	const ceiling = 8000
	start := time.Now()
	_, err = CalibratePBKDF2(hashFunc, "sha256", 32, 2000, time.Hour, ceiling, rate.time)
	if time.Since(start) > 5*time.Second {
		t.Fatal("the calibration loop ran far longer than the ceiling should allow")
	}
	var calErr *CalibrationError
	if !errors.As(err, &calErr) {
		t.Fatalf("got %v, want a *CalibrationError", err)
	}
	if calErr.Probe > ceiling {
		t.Fatalf("probe %d exceeded the ceiling %d", calErr.Probe, ceiling)
	}
}

func TestScalePBKDF2IterationsClamps(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hashAlgo string
		probe    int
		elapsed  time.Duration
		targetMs int
		want     int
	}{
		{
			name:     "a slow machine is raised to the security floor",
			hashAlgo: "sha256", probe: 1000, elapsed: 100 * time.Millisecond,
			targetMs: PBKDF2ReferenceTargetMs, want: 600_000,
		},
		{
			name:     "an implausibly fast machine is capped at the header ceiling",
			hashAlgo: "sha256", probe: 1_000_000, elapsed: time.Millisecond,
			targetMs: PBKDF2ReferenceTargetMs, want: MaxKDFIterations,
		},
		{
			name:     "the ceiling wins over a floor that exceeds it",
			hashAlgo: "sha1", probe: 1000, elapsed: time.Second,
			targetMs: MaxPBKDF2IterTimeMs, want: MaxKDFIterations,
		},
		{
			name:     "a measurement between the two is used as measured",
			hashAlgo: "sha256", probe: 100_000, elapsed: 50 * time.Millisecond,
			targetMs: PBKDF2ReferenceTargetMs, want: 4_000_000,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ScalePBKDF2Iterations(tc.hashAlgo, tc.probe, tc.elapsed, tc.targetMs)
			if got != tc.want {
				t.Fatalf("ScalePBKDF2Iterations(%q, %d, %v, %d) = %d, want %d",
					tc.hashAlgo, tc.probe, tc.elapsed, tc.targetMs, got, tc.want)
			}
			if got < MinPBKDF2Iterations {
				t.Fatalf("got %d iterations, below the absolute minimum %d", got, MinPBKDF2Iterations)
			}
		})
	}
}

func TestPBKDF2IterationFloor(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hashAlgo string
		targetMs int
		want     float64
	}{
		{"sha256 at the reference budget", "sha256", PBKDF2ReferenceTargetMs, 600_000},
		{"sha512 at the reference budget", "sha512", PBKDF2ReferenceTargetMs, 210_000},
		{"sha384 at the reference budget", "sha384", PBKDF2ReferenceTargetMs, 210_000},
		{"sha1 at the reference budget", "sha1", PBKDF2ReferenceTargetMs, 1_300_000},
		{"case is normalized", "SHA256", PBKDF2ReferenceTargetMs, 600_000},
		{"the floor scales with the budget", "sha256", PBKDF2ReferenceTargetMs / 4, 150_000},
		{"a cheap budget falls back to the absolute minimum", "sha256", 1, MinPBKDF2Iterations},
		{"an unrecommended hash gets the absolute minimum", "sha3-512", PBKDF2ReferenceTargetMs, MinPBKDF2Iterations},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := PBKDF2IterationFloor(tc.hashAlgo, tc.targetMs); got != tc.want {
				t.Fatalf("PBKDF2IterationFloor(%q, %d) = %v, want %v", tc.hashAlgo, tc.targetMs, got, tc.want)
			}
		})
	}
}

func TestCalibrateAndCalibrateWithTimer(t *testing.T) {
	iterations, err := testDeriver.Calibrate("sha256", 32, 100)
	if err != nil {
		t.Fatalf("Calibrate: %v", err)
	}
	if iterations < MinPBKDF2Iterations {
		t.Fatalf("got %d iterations, below the absolute minimum", iterations)
	}

	rate := &knownRate{perIteration: time.Microsecond}
	n, err := testDeriver.CalibrateWithTimer("sha256", 32, 2000, rate.time)
	if err != nil {
		t.Fatalf("CalibrateWithTimer: %v", err)
	}
	if n < MinPBKDF2Iterations {
		t.Fatalf("got %d iterations, below the absolute minimum", n)
	}
}

func TestCalibrateWithTimerUnsupportedHash(t *testing.T) {
	if _, err := testDeriver.CalibrateWithTimer("md5", 32, 100, WallClockPBKDF2); err == nil {
		t.Fatal("an unsupported hash was accepted")
	}
}

func TestWallClockPBKDF2(t *testing.T) {
	hashFunc, err := PBKDF2HashFunc(testDeriver.FIPS, "sha256")
	if err != nil {
		t.Fatalf("PBKDF2HashFunc: %v", err)
	}
	if _, err := WallClockPBKDF2(hashFunc, 1000, 32); err != nil {
		t.Fatalf("WallClockPBKDF2: %v", err)
	}
}
