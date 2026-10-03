// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

// Every way this command refuses to start the container is its own type. None
// of them is a test failure: each says the suite could not be started under the
// measured privilege set, and so is not started at all.

// UsageError reports a command line this command cannot split.
type UsageError struct {
	Problem string
}

func (e *UsageError) Error() string {
	return "usage: docker-run [docker flags ...] -- [command ...]: " + e.Problem
}

// NoDeviceMapperError reports a host with no device-mapper major. dm is then not
// available and the suite cannot create a mapping, so it is refused here rather
// than started into a failure that looks like a library defect.
type NoDeviceMapperError struct{}

func (e *NoDeviceMapperError) Error() string {
	return "REFUSING TO RUN: there is no device-mapper major in /proc/devices, so dm is " +
		"not available on this host and the suite cannot create a mapping. Load the " +
		"module (modprobe dm_mod) and try again"
}

// ProfileError reports that the seccomp profile could not be located. Without it
// the container either fails at docker's JSON parse, or -- worse -- runs under a
// profile without the keyring syscalls the suite exercises.
type ProfileError struct {
	// Start is the directory the search for the module root began in.
	Start string
	Err   error
}

func (e *ProfileError) Error() string {
	return "cannot locate test/integration/seccomp.json from " + e.Start +
		" (run from inside the go-luks2 checkout): " + e.Err.Error()
}

func (e *ProfileError) Unwrap() error { return e.Err }

// DockerError reports that docker itself could not be started.
type DockerError struct {
	Err error
}

func (e *DockerError) Error() string {
	return "cannot start docker: " + e.Err.Error()
}

func (e *DockerError) Unwrap() error { return e.Err }
