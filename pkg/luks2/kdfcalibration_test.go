// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"crypto/pbkdf2"
	"errors"
	"testing"
	"time"
)

// The tests in this file exist because the three that were already here did
// not. All three asserted only `iterations >= 1000`, which the hardcoded 100000
// fallback satisfied, so nothing pinned the behavior and a one-to-two order of
// magnitude weakening of every pbkdf2 keyslot survived five merges and three
// releases of green suites (issue #52).
//
// They are built to two rules the fix is worthless without:
//
//   - Every assertion here fails against the old implementation. The strongest
//     of them do so WITHOUT depending on how fast this machine is, because a
//     regression test that only fails on fast hardware is not a regression test.
//   - None of them is flaky on a slow or loaded machine. Load can only make a
//     derivation take LONGER, so the tolerances are asymmetric: tight below,
//     generous above. There is no t.Skip and no testing.Short() anywhere --
//     this project's testing rules bar both outright, and a timing test that
//     excuses itself on a busy CI box is a test that gets deleted in a month.

// timePBKDF2 returns how long one PBKDF2 derivation of the given cost actually
// takes on this machine.
func timePBKDF2(t *testing.T, hashAlgo string, keySize, iterations int) time.Duration {
	t.Helper()

	hashFunc, err := getPBKDF2HashFunc(hashAlgo)
	if err != nil {
		t.Fatalf("getPBKDF2HashFunc(%q): %v", hashAlgo, err)
	}

	salt := make([]byte, 32)
	start := time.Now()
	if _, err := pbkdf2.Key(hashFunc, "verification", salt, iterations, keySize); err != nil {
		t.Fatalf("pbkdf2.Key(%q, %d iterations): %v", hashAlgo, iterations, err)
	}
	return time.Since(start)
}

// TestBenchmarkPBKDF2CalibratesToRequestedTime is the test that would have
// caught issue #52: it RUNS the iteration count that was returned and checks
// that it costs something like the time that was asked for.
//
// The old implementation returned 100000 for every request, which is 20-50ms of
// work; against a 1000ms budget that is 20-40x under the lower bound below, so
// this fails against it by a wide margin on any hardware where the fallback was
// reachable -- which was all of it.
//
// The budget is above the library's own default, which is what makes a very
// generous band affordable: the old fallback was a FIXED 100000 iterations
// whatever was asked for, so the larger the budget the further under it that
// constant falls. Measured, that constant costs 28ms (sha256) and 118ms
// (sha512) here, against a 3000ms budget.
//
// The band is a TENTH to TEN TIMES the budget, and it is that wide on purpose.
// A timing assertion on a shared CI runner is the classic candidate for someone
// reaching for t.Skip or testing.Short() in six months -- both barred outright
// by this project's testing rules -- so the tolerance has to be wide enough
// that it is never tempting. It can afford to be: the defect this pins is a
// 25-100x error, not a 20% one. Across repeated runs on a machine deliberately
// loaded with other work the worst observed ratio was 0.46 and the worst 1.8,
// so a tenth and ten times leave roughly a 4x margin on both sides while the
// old implementation still lands 2.5x (sha512) to 10x (sha256) below the floor.
//
// The FLOOR check below is unconditional and carries no timing at all. It is
// the assertion that holds when this one cannot -- see the -race note at the
// top of TestBenchmarkPBKDF2MeetsRecommendedMinimum.
func TestBenchmarkPBKDF2CalibratesToRequestedTime(t *testing.T) {
	const targetMs = 3000
	target := targetMs * time.Millisecond

	tests := []struct {
		name     string
		hashAlgo string
		keySize  int
	}{
		{"sha256", "sha256", 32},
		{"sha512", "sha512", 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iterations, err := BenchmarkPBKDF2(tt.hashAlgo, tt.keySize, targetMs)
			if err != nil {
				t.Fatalf("BenchmarkPBKDF2(%q, %d, %d): %v", tt.hashAlgo, tt.keySize, targetMs, err)
			}

			elapsed := timePBKDF2(t, tt.hashAlgo, tt.keySize, iterations)
			t.Logf("%s: calibrated %d iterations for %v, measured %v", tt.hashAlgo, iterations, target, elapsed)

			// Checked FIRST and unconditionally. An earlier version of this test
			// only consulted the floor to decide whether to apply the upper
			// bound, which let a count BELOW the floor through the "the floor
			// set this" branch and skip the remaining checks -- measured: a
			// mutant returning 500000 against a 600000 floor was reported as
			// floored and passed. A bound used to classify must also be
			// asserted.
			floor := pbkdf2IterationFloor(tt.hashAlgo, targetMs)
			if float64(iterations) < floor {
				t.Fatalf("%s: got %d iterations, below the floor of %v for a %dms budget",
					tt.hashAlgo, iterations, floor, targetMs)
			}

			if lower := target / 10; elapsed < lower {
				t.Fatalf("%s: %d iterations cost %v, which is below %v -- the count is calibrated far under the %v that was requested",
					tt.hashAlgo, iterations, elapsed, lower, target)
			}

			// The upper bound is skipped -- and only ever skipped -- when the
			// count did not come from the measurement at all. Both clamps
			// legitimately produce a count that costs more than the budget: the
			// security floor on hardware too slow to earn it, the header ceiling
			// on a budget too large to fit. Asserting the budget against a
			// clamped count would be asserting the wrong thing, not tolerating a
			// failure.
			if float64(iterations) <= floor {
				t.Logf("%s: count came from the security floor, not the measurement", tt.hashAlgo)
				return
			}
			if iterations == maxKDFIterations {
				t.Logf("%s: count came from the header ceiling, not the measurement", tt.hashAlgo)
				return
			}

			if upper := 10 * target; elapsed > upper {
				t.Fatalf("%s: %d iterations cost %v, which is above %v -- the extrapolation overshot the %v that was requested",
					tt.hashAlgo, iterations, elapsed, upper, target)
			}
		})
	}
}

// TestBenchmarkPBKDF2ScalesWithRequestedTime pins the same property without
// depending on this machine's speed at all: four times the budget must buy
// about four times the iterations.
//
// It is the more robust half of the pair. Both calibrations run back to back
// under identical conditions, so the ratio survives a machine that is slow, a
// machine that is loaded, and a machine whose count is being set by the
// security floor -- the floor scales with the budget too. The old
// implementation returned the same 100000 for both budgets, a ratio of 1.
//
// The two budgets are twenty times apart rather than four, which is what makes
// the band affordable. Each calibration carries its own measurement noise, and
// the ratio compounds both: measured over ten runs on a loaded machine, two
// budgets 4x apart produced ratios from 2.57 to 7.13 -- a spread that leaves no
// room around a band tight enough to mean anything. Twenty times apart, the
// same spread sits comfortably inside 4..100 while the constant-returning
// implementation still scores 1.
func TestBenchmarkPBKDF2ScalesWithRequestedTime(t *testing.T) {
	const (
		shortMs = 100
		longMs  = 2000
	)

	short, err := BenchmarkPBKDF2("sha256", 32, shortMs)
	if err != nil {
		t.Fatalf("BenchmarkPBKDF2 at %dms: %v", shortMs, err)
	}
	long, err := BenchmarkPBKDF2("sha256", 32, longMs)
	if err != nil {
		t.Fatalf("BenchmarkPBKDF2 at %dms: %v", longMs, err)
	}

	ratio := float64(long) / float64(short)
	t.Logf("%dms -> %d iterations, %dms -> %d iterations, ratio %.2f (expected %.1f)",
		shortMs, short, longMs, long, ratio, float64(longMs)/float64(shortMs))

	// Expected ratio is 20, and the band is a fifth to five times that. A count
	// that ignores the budget scores 1, four times below the lower bound.
	if ratio < 4 || ratio > 100 {
		t.Fatalf("iteration count does not scale with the requested time: %dms gave %d and %dms gave %d (ratio %.2f, want 4..100)",
			shortMs, short, longMs, long, ratio)
	}
}

// TestBenchmarkPBKDF2MeetsRecommendedMinimum is the hardware-independent form
// of the regression: at the library's own default budget the count must be at
// least the OWASP recommendation for the hash.
//
// No timing is involved, so it holds on every machine. The old implementation
// returned 100000 at this budget, six times under the sha256 minimum, and this
// fails against it deterministically.
//
// # The -race inversion, which is the trap in this whole subsystem
//
// It fails against it deterministically IN AN ORDINARY BUILD. Under -race the
// instrumentation slows the old probe past the 1ms threshold its gate tested,
// so the gate PASSES, the extrapolation runs, and the broken implementation
// returns a plausible 500000-1000000 -- above this floor, and scaling correctly
// with the budget. Measured, not reasoned: every test in this file passes
// against the restored defect under -race.
//
// The consequence is not about these tests, it is about how they are RUN. The
// defect exists only in the uninstrumented build, so a suite executed solely
// under -race cannot see it -- which is how it survived five merges of green
// CI. `make test-calibration` runs these tests without -race for exactly that
// reason and is wired into `make ci`; do not consolidate it into the -race
// unit-test target on the grounds that it duplicates coverage. It does not.
func TestBenchmarkPBKDF2MeetsRecommendedMinimum(t *testing.T) {
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
			iterations, err := BenchmarkPBKDF2(tt.hashAlgo, tt.keySize, pbkdf2ReferenceTargetMs)
			if err != nil {
				t.Fatalf("BenchmarkPBKDF2(%q, %d, %d): %v", tt.hashAlgo, tt.keySize, pbkdf2ReferenceTargetMs, err)
			}

			want := pbkdf2RecommendedIterations[tt.hashAlgo]
			t.Logf("%s at %dms: %d iterations (recommended minimum %d)", tt.hashAlgo, pbkdf2ReferenceTargetMs, iterations, want)

			if iterations < want {
				t.Fatalf("%s at the %dms default: got %d iterations, want at least the recommended %d",
					tt.hashAlgo, pbkdf2ReferenceTargetMs, iterations, want)
			}
			if iterations > maxKDFIterations {
				t.Fatalf("%s: got %d iterations, above the %d ceiling validateKDFCost enforces on read-back",
					tt.hashAlgo, iterations, maxKDFIterations)
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
			iterations, err := BenchmarkPBKDF2("sha256", 32, tt.targetMs)
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

// TestCalibratePBKDF2FailsClosedWhenUnmeasurable exercises the path a stopped
// clock reaches: no probe up to the ceiling ran long enough to be timed.
//
// It is driven through the probe bounds rather than through a fake clock, which
// is why calibratePBKDF2 takes them. A floor of an hour is never cleared, and a
// ceiling at the starting probe stops the doubling after one round -- so the
// failure is deterministic and costs one 1000-iteration derivation.
//
// This is the case the old implementation answered with `return 100000, nil`.
func TestCalibratePBKDF2FailsClosedWhenUnmeasurable(t *testing.T) {
	hashFunc, err := getPBKDF2HashFunc("sha256")
	if err != nil {
		t.Fatalf("getPBKDF2HashFunc: %v", err)
	}

	iterations, err := calibratePBKDF2(hashFunc, "sha256", 32, 2000, time.Hour, pbkdf2ProbeStart)
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
	if calErr.Elapsed <= 0 {
		t.Fatalf("error reports elapsed %v; the probe did run and its measurement is what could not be used", calErr.Elapsed)
	}
}

// TestCalibratePBKDF2StopsDoublingAtTheCeiling pins that the ceiling bounds the
// WORK and not just the loop. A clock that never advances must not be answered
// by a derivation that runs for minutes before failing.
func TestCalibratePBKDF2StopsDoublingAtTheCeiling(t *testing.T) {
	hashFunc, err := getPBKDF2HashFunc("sha256")
	if err != nil {
		t.Fatalf("getPBKDF2HashFunc: %v", err)
	}

	// A ceiling of 4000 admits probes of 1000, 2000 and 4000 and then refuses:
	// 4000 is not <= 4000/2. The largest probe RUN is the ceiling itself, never
	// a doubling past it.
	const ceiling = 4 * pbkdf2ProbeStart

	_, err = calibratePBKDF2(hashFunc, "sha256", 32, 2000, time.Hour, ceiling)
	var calErr *KDFCalibrationError
	if !errors.As(err, &calErr) {
		t.Fatalf("got error %v, want a *KDFCalibrationError", err)
	}

	// This is also what pins the DOUBLING itself. An implementation that went
	// back to one fixed probe would report pbkdf2ProbeStart here, whatever floor
	// it was given -- and a fixed probe is half of what issue #52 was: no single
	// iteration count can be a meaningful measurement on both a fast server and
	// a slow board.
	if calErr.Probe == pbkdf2ProbeStart {
		t.Fatalf("the probe never grew past its starting size of %d; the calibration is not scaling the probe to the machine", pbkdf2ProbeStart)
	}
	if calErr.Probe != ceiling {
		t.Fatalf("largest probe run was %d, want the ceiling %d", calErr.Probe, ceiling)
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
			// ceiling validateKDFCost applies on read-back.
			name:     "an implausibly fast machine is capped at the header ceiling",
			hashAlgo: "sha256", probe: 1_000_000, elapsed: time.Millisecond,
			targetMs: pbkdf2ReferenceTargetMs, want: maxKDFIterations,
		},
		{
			// A budget whose floor alone exceeds the ceiling must land ON the
			// ceiling: the floor is applied first and the ceiling second.
			name:     "the ceiling wins over a floor that exceeds it",
			hashAlgo: "sha1", probe: 1000, elapsed: time.Second,
			targetMs: maxPBKDF2IterTimeMs, want: maxKDFIterations,
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

// TestCreateKDFPBKDF2CalibratesTheKeyslot pins the property at the level that
// actually reaches the disk: the iteration count CreateKDF puts in the keyslot
// is the calibrated one, not a constant.
//
// This is where issue #52 did its damage. BenchmarkPBKDF2 is exported and could
// have been fixed while createPBKDF2KDF kept ignoring it; the header is what an
// attacker gets, so the header is what this asserts.
func TestCreateKDFPBKDF2CalibratesTheKeyslot(t *testing.T) {
	kdf, err := CreateKDF(FormatOptions{KDFType: KDFTypePBKDF2SHA256}, 32)
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
	if err := validateKDFCost(kdf); err != nil {
		t.Fatalf("the KDF CreateKDF produced does not pass its own read-back validation: %v", err)
	}
}

// TestCreateKDFPBKDF2RejectsUnusableIterTime pins that the refusal propagates:
// an unusable PBKDFIterTime fails the format rather than silently producing a
// keyslot with some other cost.
func TestCreateKDFPBKDF2RejectsUnusableIterTime(t *testing.T) {
	kdf, err := CreateKDF(FormatOptions{KDFType: KDFTypePBKDF2SHA256, PBKDFIterTime: -1}, 32)
	if err == nil {
		t.Fatalf("CreateKDF with a negative PBKDFIterTime produced a keyslot with %v iterations", kdf.Iterations)
	}
	if !errors.Is(err, ErrKDFCalibration) {
		t.Fatalf("got error %v, want one matching ErrKDFCalibration", err)
	}
}

// TestAddKeyFormatOptionsPropagatesTheIterTime pins the contract that made
// Codex's review finding a real one: an unusable PBKDFIterTime must reach the
// calibration and be REFUSED, whichever API the caller came through.
//
// AddKey used to copy the budget only when it was > 0, so a negative arrived at
// CreateKDF as zero and became the 2000ms default. That was invisible before
// the calibration validated anything; once FormatOptions started refusing an
// unusable budget, the same value errored on one path and was silently ignored
// on the other. Two contracts for one parameter is the defect, not the
// direction of the difference.
func TestAddKeyFormatOptionsPropagatesTheIterTime(t *testing.T) {
	tests := []struct {
		name string
		opts *AddKeyOptions
		want int
	}{
		{"nil options leave it unset", nil, 0},
		{"unset stays unset so the default applies", &AddKeyOptions{KDFType: KDFTypePBKDF2}, 0},
		{"a usable budget is carried", &AddKeyOptions{KDFType: KDFTypePBKDF2, PBKDFIterTime: 500}, 500},
		{"a negative budget is carried, not dropped", &AddKeyOptions{KDFType: KDFTypePBKDF2, PBKDFIterTime: -1}, -1},
		{"an out-of-range budget is carried, not dropped", &AddKeyOptions{KDFType: KDFTypePBKDF2, PBKDFIterTime: maxPBKDF2IterTimeMs + 1}, maxPBKDF2IterTimeMs + 1},
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
	opts := baseAddKeyFormatOptions(&AddKeyOptions{KDFType: KDFTypePBKDF2, PBKDFIterTime: -1})

	kdf, err := CreateKDF(opts, 32)
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

	if got.KDFType != KDFTypeArgon2id {
		t.Fatalf("default KDFType = %q, want %q", got.KDFType, KDFTypeArgon2id)
	}
	if got.HashAlgo != DefaultHashAlgo {
		t.Fatalf("default HashAlgo = %q, want %q", got.HashAlgo, DefaultHashAlgo)
	}
	if got.Argon2Time != 4 || got.Argon2Memory != 1048576 || got.Argon2Parallel != 4 {
		t.Fatalf("default Argon2 costs = time %d, memory %d, parallel %d; want 4, 1048576, 4",
			got.Argon2Time, got.Argon2Memory, got.Argon2Parallel)
	}

	// An explicit choice overrides each default.
	custom := baseAddKeyFormatOptions(&AddKeyOptions{
		KDFType: KDFTypePBKDF2SHA512, Hash: "sha512",
		Argon2Time: 8, Argon2Memory: 2048, Argon2Parallel: 2,
	})
	if custom.KDFType != KDFTypePBKDF2SHA512 || custom.HashAlgo != "sha512" ||
		custom.Argon2Time != 8 || custom.Argon2Memory != 2048 || custom.Argon2Parallel != 2 {
		t.Fatalf("explicit options were not carried through: %+v", custom)
	}
}
