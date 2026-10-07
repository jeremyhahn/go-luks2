// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-luks2/internal/clock"
)

// ghCanceled is GitHub's own spelling of a canceled check run's conclusion,
// and of Gitea's equivalent: the value the API returns, not prose.
const ghCanceled = "cancelled" //nolint:misspell // the API's spelling, not prose

const (
	sha     = "0123456789abcdef0123456789abcdef01234567"
	gateCtx = "CI / CI Gate (push)"
	gateJob = "CI Gate"
	ciFile  = "ci.yml"
)

// forge serves one scripted answer per request, repeating the last.
type forge struct {
	answers []func(w http.ResponseWriter, r *http.Request)
	calls   int
	paths   []string
	auth    []string
}

func (f *forge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	i := f.calls
	if i >= len(f.answers) {
		i = len(f.answers) - 1
	}
	f.calls++
	f.paths = append(f.paths, r.URL.RequestURI())
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	f.answers[i](w, r)
}

func giteaJSON(total int, pairs ...string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		var s giteaStatus
		s.TotalCount = total
		for i := 0; i+1 < len(pairs); i += 2 {
			s.Statuses = append(s.Statuses, struct {
				Context string `json:"context"`
				Status  string `json:"status"`
			}{pairs[i], pairs[i+1]})
		}
		_ = json.NewEncoder(w).Encode(s)
	}
}

// ghRun is one workflow run on the fake GitHub, with the jobs of its latest
// attempt; jobs answers in order per poll, repeating the last.
type ghRun struct {
	id                         int64
	sha, event, branch, status string
	conclusion                 string
	jobs                       [][][3]string // per poll: {name, status, conclusion}
	polls                      int
}

// fakeGitHub serves the Actions API for ci.yml's runs and their jobs.
type fakeGitHub struct {
	runs  []*ghRun
	paths []string
	auth  []string
}

func (g *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.paths = append(g.paths, r.URL.RequestURI())
	g.auth = append(g.auth, r.Header.Get("Authorization"))
	runsPath := "/repos/owner/repo/actions/workflows/" + ciFile + "/runs"
	if r.URL.Path == runsPath {
		var out githubRuns
		for _, run := range g.runs {
			out.WorkflowRuns = append(out.WorkflowRuns, struct {
				ID         int64  `json:"id"`
				HeadSHA    string `json:"head_sha"`
				Event      string `json:"event"`
				HeadBranch string `json:"head_branch"`
				Status     string `json:"status"`
				Conclusion string `json:"conclusion"`
			}{run.id, run.sha, run.event, run.branch, run.status, run.conclusion})
		}
		_ = json.NewEncoder(w).Encode(out)
		return
	}
	for _, run := range g.runs {
		if r.URL.Path != fmt.Sprintf("/repos/owner/repo/actions/runs/%d/jobs", run.id) {
			continue
		}
		i := run.polls
		if i >= len(run.jobs) {
			i = len(run.jobs) - 1
		}
		run.polls++
		var out githubJobs
		if i >= 0 {
			for _, j := range run.jobs[i] {
				out.Jobs = append(out.Jobs, struct {
					Name       string `json:"name"`
					Status     string `json:"status"`
					Conclusion string `json:"conclusion"`
				}{j[0], j[1], j[2]})
			}
		}
		_ = json.NewEncoder(w).Encode(out)
		return
	}
	http.NotFound(w, r)
}

func httpStatus(code int) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", code)
	}
}

// testHost wires a fake forge and git. gitStatus is merge-base's exit status.
func testHost(t *testing.T, srv *httptest.Server, server string, gitStatus int, clk clock.Clock) (host, *[][]string) {
	t.Helper()
	var gitCalls [][]string
	env := map[string]string{
		"GITHUB_SERVER_URL": server,
		"GITHUB_API_URL":    srv.URL,
		"GITHUB_REPOSITORY": "owner/repo",
		"FORGE_TOKEN":       "secret-token",
	}
	return host{
		getenv: func(k string) string { return env[k] },
		git: func(args ...string) (int, string, error) {
			gitCalls = append(gitCalls, args)
			return gitStatus, "", nil
		},
		client: srv.Client(),
		clock:  clk,
	}, &gitCalls
}

func args(extra ...string) []string {
	return append([]string{"-sha", sha, "-main-ref", "FETCH_HEAD",
		"-status-context", gateCtx, "-workflow", ciFile, "-job-name", gateJob,
		"-timeout", "10m", "-poll", "1m"}, extra...)
}

func run(t *testing.T, h host, argv []string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := cli(argv, &out, &errb, h)
	return code, out.String(), errb.String()
}

func TestGiteaGatePassedReleases(t *testing.T) {
	f := &forge{answers: []func(http.ResponseWriter, *http.Request){
		giteaJSON(2, "CI / Lint (push)", "success", gateCtx, "success"),
	}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	clk := clock.NewFake(t)
	h, gitCalls := testHost(t, srv, srv.URL, 0, clk)

	code, out, stderr := run(t, h, args())
	if code != 0 {
		t.Fatalf("exit %d, stderr %s", code, stderr)
	}
	if !strings.Contains(out, "passed") {
		t.Errorf("stdout does not report the pass: %s", out)
	}
	want := []string{"merge-base", "--is-ancestor", sha, "FETCH_HEAD"}
	if len(*gitCalls) != 1 || strings.Join((*gitCalls)[0], " ") != strings.Join(want, " ") {
		t.Errorf("git calls = %v, want %v", *gitCalls, want)
	}
	if got := f.paths[0]; got != "/api/v1/repos/owner/repo/commits/"+sha+"/status?limit=50&page=1" {
		t.Errorf("path = %s", got)
	}
	if f.auth[0] != "token secret-token" {
		t.Errorf("Authorization = %q", f.auth[0])
	}
}

// The release commit and its tag land together, so CI is normally still
// running: the gate must wait for it rather than read it once.
func TestGiteaGateWaitsForAPendingGate(t *testing.T) {
	f := &forge{answers: []func(http.ResponseWriter, *http.Request){
		giteaJSON(1, "CI / Lint (push)", "pending"),
		giteaJSON(2, "CI / Lint (push)", "success", gateCtx, "pending"),
		httpStatus(http.StatusBadGateway),
		giteaJSON(2, "CI / Lint (push)", "success", gateCtx, "success"),
	}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	clk := clock.NewFake(t)
	h, _ := testHost(t, srv, srv.URL, 0, clk)

	if code, _, stderr := run(t, h, args()); code != 0 {
		t.Fatalf("exit %d, stderr %s", code, stderr)
	}
	if len(clk.Waits()) != 3 {
		t.Errorf("slept %d times, want 3 (two pending readings and one 502)", len(clk.Waits()))
	}
}

func TestGiteaGateFailureRefuses(t *testing.T) {
	for _, state := range []string{"failure", "error", "warning", ghCanceled} {
		t.Run(state, func(t *testing.T) {
			f := &forge{answers: []func(http.ResponseWriter, *http.Request){giteaJSON(1, gateCtx, state)}}
			srv := httptest.NewServer(f)
			defer srv.Close()
			clk := clock.NewFake(t)
			h, _ := testHost(t, srv, srv.URL, 0, clk)

			var out, errb bytes.Buffer
			req, err := parseArgs(args(), &errb)
			if err != nil {
				t.Fatal(err)
			}
			err = gate(&out, h, req)
			var failed *GateFailedError
			if !errors.As(err, &failed) || failed.State != state {
				t.Fatalf("err = %v, want *GateFailedError with state %q", err, state)
			}
			if len(clk.Waits()) != 0 {
				t.Errorf("a finished gate was waited on (%d sleeps)", len(clk.Waits()))
			}
		})
	}
}

// The PR-event context of the same job is not the gate for a push to main.
func TestGiteaGateIgnoresOtherContexts(t *testing.T) {
	f := &forge{answers: []func(http.ResponseWriter, *http.Request){
		giteaJSON(1, "CI / CI Gate (pull_request)", "success"),
	}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	clk := clock.NewFake(t)
	h, _ := testHost(t, srv, srv.URL, 0, clk)

	var out, errb bytes.Buffer
	req, _ := parseArgs(args(), &errb)
	err := gate(&out, h, req)
	var timeout *GateTimeoutError
	if !errors.As(err, &timeout) {
		t.Fatalf("err = %v, want *GateTimeoutError", err)
	}
	if len(clk.Waits()) != 10 {
		t.Errorf("slept %d times over a 10m timeout at 1m polls, want 10", len(clk.Waits()))
	}
}

func TestGiteaGatePagesToFindTheContext(t *testing.T) {
	f := &forge{answers: []func(http.ResponseWriter, *http.Request){
		giteaJSON(3, "a", "success", "b", "success"),
		giteaJSON(3, gateCtx, "success"),
	}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	clk := clock.NewFake(t)
	h, _ := testHost(t, srv, srv.URL, 0, clk)

	if code, _, stderr := run(t, h, args()); code != 0 {
		t.Fatalf("exit %d, stderr %s", code, stderr)
	}
	if len(f.paths) != 2 || !strings.HasSuffix(f.paths[1], "page=2") {
		t.Errorf("paths = %v, want a second page", f.paths)
	}
	if len(clk.Waits()) != 0 {
		t.Errorf("slept %d times", len(clk.Waits()))
	}
}

func TestGateTimeoutKeepsTheLastTransientError(t *testing.T) {
	f := &forge{answers: []func(http.ResponseWriter, *http.Request){httpStatus(http.StatusServiceUnavailable)}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	clk := clock.NewFake(t)
	h, _ := testHost(t, srv, srv.URL, 0, clk)

	var out, errb bytes.Buffer
	req, _ := parseArgs(args(), &errb)
	err := gate(&out, h, req)
	var timeout *GateTimeoutError
	if !errors.As(err, &timeout) || timeout.LastErr == nil {
		t.Fatalf("err = %v, want *GateTimeoutError carrying the last error", err)
	}
	var status *HTTPStatusError
	if !errors.As(err, &status) || status.Status != http.StatusServiceUnavailable {
		t.Errorf("err does not reach the HTTP 503: %v", err)
	}
	if !strings.Contains(err.Error(), "last error") {
		t.Errorf("message omits the last error: %v", err)
	}
}

func TestForgeRefusalIsFinal(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusNotFound} {
		f := &forge{answers: []func(http.ResponseWriter, *http.Request){httpStatus(code)}}
		srv := httptest.NewServer(f)
		clk := clock.NewFake(t)
		h, _ := testHost(t, srv, srv.URL, 0, clk)

		var out, errb bytes.Buffer
		req, _ := parseArgs(args(), &errb)
		err := gate(&out, h, req)
		var forgeErr *ForgeError
		if !errors.As(err, &forgeErr) || forgeErr.Status != code {
			t.Errorf("HTTP %d: err = %v, want *ForgeError", code, err)
		}
		if len(clk.Waits()) != 0 {
			t.Errorf("HTTP %d was retried", code)
		}
		srv.Close()
	}
}

func TestMalformedForgeAnswerIsFinal(t *testing.T) {
	f := &forge{answers: []func(http.ResponseWriter, *http.Request){
		func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) },
	}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	clk := clock.NewFake(t)
	h, _ := testHost(t, srv, srv.URL, 0, clk)

	var out, errb bytes.Buffer
	req, _ := parseArgs(args(), &errb)
	err := gate(&out, h, req)
	var forgeErr *ForgeError
	if !errors.As(err, &forgeErr) || forgeErr.Err == nil {
		t.Fatalf("err = %v, want *ForgeError wrapping the decode error", err)
	}
	if !strings.Contains(err.Error(), "reading ") {
		t.Errorf("message = %v", err)
	}
}

func TestUnreachableForgeIsTransient(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close() // nothing listens
	clk := clock.NewFake(t)
	h, _ := testHost(t, srv, srv.URL, 0, clk)

	var out, errb bytes.Buffer
	req, _ := parseArgs(args("-timeout", "2m"), &errb)
	err := gate(&out, h, req)
	var timeout *GateTimeoutError
	if !errors.As(err, &timeout) {
		t.Fatalf("err = %v, want *GateTimeoutError", err)
	}
	if len(clk.Waits()) != 2 {
		t.Errorf("sleeps = %d, want 2", len(clk.Waits()))
	}
}

func TestNotOnMainRefusesBeforeReadingCI(t *testing.T) {
	f := &forge{answers: []func(http.ResponseWriter, *http.Request){giteaJSON(1, gateCtx, "success")}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	clk := clock.NewFake(t)
	h, _ := testHost(t, srv, srv.URL, 1, clk)

	var out, errb bytes.Buffer
	req, _ := parseArgs(args(), &errb)
	err := gate(&out, h, req)
	var notOnMain *NotOnMainError
	if !errors.As(err, &notOnMain) {
		t.Fatalf("err = %v, want *NotOnMainError", err)
	}
	if !strings.Contains(err.Error(), "not on main") {
		t.Errorf("message = %v", err)
	}
	if f.calls != 0 {
		t.Errorf("CI was read for a commit not on main")
	}
}

func TestAncestryUnansweredRefuses(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	clk := clock.NewFake(t)

	// git exits 128 (unknown commit, missing ref).
	h, _ := testHost(t, srv, srv.URL, 128, clk)
	var out, errb bytes.Buffer
	req, _ := parseArgs(args(), &errb)
	err := gate(&out, h, req)
	var anc *AncestryError
	var exit *ExitStatusError
	if !errors.As(err, &anc) || !errors.As(err, &exit) || exit.Status != 128 {
		t.Fatalf("err = %v, want *AncestryError wrapping exit 128", err)
	}
	if !strings.Contains(err.Error(), "exited 128") {
		t.Errorf("message = %v", err)
	}

	// git could not run at all.
	h.git = func(...string) (int, string, error) { return -1, "", errNoGit }
	err = gate(&out, h, req)
	if !errors.As(err, &anc) || !errors.Is(err, errNoGit) {
		t.Fatalf("err = %v, want *AncestryError wrapping errNoGit", err)
	}
}

var errNoGit = errors.New("git: executable not found")

func TestGitHubGatePassed(t *testing.T) {
	push := &ghRun{id: 7, sha: sha, event: "push", branch: "main", status: "in_progress",
		jobs: [][][3]string{
			{{"Lint", "completed", "success"}},
			{{"Lint", "completed", "success"}, {gateJob, "in_progress", ""}},
			{{"Lint", "completed", "success"}, {gateJob, "completed", "success"}},
		}}
	g := &fakeGitHub{runs: []*ghRun{push}}
	srv := httptest.NewServer(g)
	defer srv.Close()
	clk := clock.NewFake(t)
	h, _ := testHost(t, srv, githubServer, 0, clk)

	if code, out, stderr := run(t, h, args()); code != 0 {
		t.Fatalf("exit %d\n%s%s", code, out, stderr)
	}
	want := "/repos/owner/repo/actions/workflows/ci.yml/runs?head_sha=" + sha + "&event=push&branch=main&per_page=100"
	if g.paths[0] != want {
		t.Errorf("path = %s, want %s", g.paths[0], want)
	}
	if g.paths[1] != "/repos/owner/repo/actions/runs/7/jobs?filter=latest&per_page=100" {
		t.Errorf("jobs path = %s", g.paths[1])
	}
	if g.auth[0] != "Bearer secret-token" {
		t.Errorf("Authorization = %q", g.auth[0])
	}
	if len(clk.Waits()) != 2 {
		t.Errorf("sleeps = %d, want 2 (gate job not created, then running)", len(clk.Waits()))
	}
}

// Codex review round 2: a check run named "CI Gate" that passed is not
// evidence. Here the pull_request run of the SAME commit passed (and has the
// higher id), another commit's push run passed, and a run on another branch
// passed -- but this commit's push to main failed its gate. That failure is
// the answer.
func TestGitHubGateIgnoresEveryRunButThisCommitsPushToMain(t *testing.T) {
	passed := [][][3]string{{{gateJob, "completed", "success"}}}
	g := &fakeGitHub{runs: []*ghRun{
		{id: 9, sha: sha, event: "pull_request", branch: "feature", status: "completed", jobs: passed},
		{id: 8, sha: strings.Repeat("e", 40), event: "push", branch: "main", status: "completed", jobs: passed},
		{id: 6, sha: sha, event: "push", branch: "release", status: "completed", jobs: passed},
		{id: 7, sha: sha, event: "push", branch: "main", status: "completed", conclusion: "failure",
			jobs: [][][3]string{{{gateJob, "completed", "failure"}}}},
	}}
	srv := httptest.NewServer(g)
	defer srv.Close()
	clk := clock.NewFake(t)
	h, _ := testHost(t, srv, githubServer, 0, clk)

	var out, errb bytes.Buffer
	req, _ := parseArgs(args(), &errb)
	err := gate(&out, h, req)
	var failed *GateFailedError
	if !errors.As(err, &failed) || failed.State != "failure" {
		t.Fatalf("err = %v, want *GateFailedError(failure)", err)
	}
	if !strings.Contains(err.Error(), "re-run CI") {
		t.Errorf("message lacks the remedy: %v", err)
	}
}

// A re-run is the same run id with a new attempt; filter=latest returns the
// latest attempt's jobs, and the latest run id wins over an older one.
func TestGitHubGateUsesTheLatestRun(t *testing.T) {
	g := &fakeGitHub{runs: []*ghRun{
		{id: 3, sha: sha, event: "push", branch: "main", status: "completed",
			jobs: [][][3]string{{{gateJob, "completed", ghCanceled}}}},
		{id: 4, sha: sha, event: "push", branch: "main", status: "completed",
			jobs: [][][3]string{{{gateJob, "completed", "success"}}}},
	}}
	srv := httptest.NewServer(g)
	defer srv.Close()
	clk := clock.NewFake(t)
	h, _ := testHost(t, srv, githubServer, 0, clk)
	if code, out, stderr := run(t, h, args()); code != 0 {
		t.Fatalf("exit %d\n%s%s", code, out, stderr)
	}
}

// A run that finished without ever creating the gate job (canceled before
// the gate) will not create it by waiting.
func TestGitHubRunThatEndedWithoutTheGateJobFails(t *testing.T) {
	g := &fakeGitHub{runs: []*ghRun{
		{id: 7, sha: sha, event: "push", branch: "main", status: "completed", conclusion: ghCanceled,
			jobs: [][][3]string{{{"Lint", "completed", ghCanceled}}}},
	}}
	srv := httptest.NewServer(g)
	defer srv.Close()
	clk := clock.NewFake(t)
	h, _ := testHost(t, srv, githubServer, 0, clk)

	var out, errb bytes.Buffer
	req, _ := parseArgs(args(), &errb)
	err := gate(&out, h, req)
	var failed *GateFailedError
	if !errors.As(err, &failed) || !strings.Contains(failed.State, "without a CI Gate job") {
		t.Fatalf("err = %v, want *GateFailedError naming the missing job", err)
	}
	if len(clk.Waits()) != 0 {
		t.Errorf("a finished run was waited on (%d sleeps)", len(clk.Waits()))
	}
}

func TestGitHubNoRunYetWaitsThenTimesOut(t *testing.T) {
	g := &fakeGitHub{}
	srv := httptest.NewServer(g)
	defer srv.Close()
	clk := clock.NewFake(t)
	h, _ := testHost(t, srv, githubServer, 0, clk)

	var out, errb bytes.Buffer
	req, _ := parseArgs(args(), &errb)
	err := gate(&out, h, req)
	var timeout *GateTimeoutError
	if !errors.As(err, &timeout) {
		t.Fatalf("err = %v, want *GateTimeoutError", err)
	}
}

func TestGitHubJobsRefusalIsFinal(t *testing.T) {
	g := &fakeGitHub{runs: []*ghRun{{id: 7, sha: sha, event: "push", branch: "main", status: "in_progress"}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/jobs") {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		g.ServeHTTP(w, r)
	}))
	defer srv.Close()
	clk := clock.NewFake(t)
	h, _ := testHost(t, srv, githubServer, 0, clk)

	var out, errb bytes.Buffer
	req, _ := parseArgs(args(), &errb)
	err := gate(&out, h, req)
	var forgeErr *ForgeError
	if !errors.As(err, &forgeErr) || forgeErr.Status != http.StatusForbidden {
		t.Fatalf("err = %v, want *ForgeError(403)", err)
	}
}

func TestGitHubDefaultAPIURL(t *testing.T) {
	h := host{getenv: func(k string) string {
		return map[string]string{"GITHUB_SERVER_URL": githubServer, "GITHUB_REPOSITORY": "o/r", "FORGE_TOKEN": "t"}[k]
	}}
	var errb bytes.Buffer
	req, _ := parseArgs(args(), &errb)
	read, name, err := gateReader(h, req)
	if err != nil || read == nil || name != ciFile+" / "+gateJob {
		t.Fatalf("gateReader = %v, %q, %v", read, name, err)
	}
}

func TestEnvironmentIsRequired(t *testing.T) {
	cases := map[string]map[string]string{
		"no server": {"GITHUB_REPOSITORY": "o/r", "FORGE_TOKEN": "t"},
		"bad repo":  {"GITHUB_SERVER_URL": "https://forge", "GITHUB_REPOSITORY": "o", "FORGE_TOKEN": "t"},
		"no token":  {"GITHUB_SERVER_URL": "https://forge", "GITHUB_REPOSITORY": "o/r"},
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			h := host{getenv: func(k string) string { return env[k] },
				git: func(...string) (int, string, error) { return 0, "", nil }}
			var out, errb bytes.Buffer
			req, _ := parseArgs(args(), &errb)
			var usage *UsageError
			if err := gate(&out, h, req); !errors.As(err, &usage) {
				t.Fatalf("err = %v, want *UsageError", err)
			}
		})
	}
}

func TestParseArgsRefusesBadInput(t *testing.T) {
	base := map[string]string{"-sha": sha, "-main-ref": "FETCH_HEAD", "-status-context": gateCtx,
		"-workflow": ciFile, "-job-name": gateJob}
	build := func(over map[string]string, extra ...string) []string {
		var a []string
		for _, k := range []string{"-sha", "-main-ref", "-status-context", "-workflow", "-job-name"} {
			v := base[k]
			if o, ok := over[k]; ok {
				v = o
			}
			a = append(a, k, v)
		}
		return append(a, extra...)
	}
	cases := map[string][]string{
		"short sha":      build(map[string]string{"-sha": "abc123"}),
		"upper-case sha": build(map[string]string{"-sha": strings.ToUpper(sha)}),
		"no main ref":    build(map[string]string{"-main-ref": ""}),
		"option ref":     build(map[string]string{"-main-ref": "--output=x"}),
		"no context":     build(map[string]string{"-status-context": ""}),
		"no workflow":    build(map[string]string{"-workflow": ""}),
		"workflow path":  build(map[string]string{"-workflow": "../x.yml"}),
		"no job name":    build(map[string]string{"-job-name": ""}),
		"zero timeout":   build(nil, "-timeout", "0s"),
		"stray argument": build(nil, "extra"),
		"unknown flag":   build(nil, "-bogus"),
	}
	for name, a := range cases {
		t.Run(name, func(t *testing.T) {
			var errb bytes.Buffer
			_, err := parseArgs(a, &errb)
			var usage *UsageError
			if !errors.As(err, &usage) {
				t.Fatalf("err = %v, want *UsageError", err)
			}
			if !strings.Contains(err.Error(), "usage: release-gate") {
				t.Errorf("message = %v", err)
			}
		})
	}
}

func TestCLIExitStatus(t *testing.T) {
	var out, errb bytes.Buffer
	if code := cli([]string{"-sha", "x"}, &out, &errb, host{}); code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	if !strings.HasPrefix(errb.String(), "FAIL:") {
		t.Errorf("stderr = %q", errb.String())
	}
}

func TestSystemHostRunsGit(t *testing.T) {
	h := systemHost()
	if h.client == nil || h.clock == nil || h.getenv == nil {
		t.Fatal("systemHost left a field unset")
	}
	// The repository's own HEAD is an ancestor of itself: exit 0.
	status, out, err := h.git("merge-base", "--is-ancestor", "HEAD", "HEAD")
	if err != nil || status != 0 {
		t.Fatalf("git merge-base HEAD HEAD = %d, %q, %v", status, out, err)
	}
	// An unknown revision is git's own non-zero exit, not a failure to run.
	status, _, err = h.git("merge-base", "--is-ancestor", strings.Repeat("f", 40), "HEAD")
	if err != nil || status == 0 || status == 1 {
		t.Fatalf("unknown commit: status %d, err %v; want a status other than 0 and 1", status, err)
	}
}

func TestErrorMessages(t *testing.T) {
	for _, e := range []error{
		&ForgeError{URL: "u", Status: 404, Body: "nope"},
		&transientError{URL: "u", Err: &HTTPStatusError{Status: 502}},
		&GateTimeoutError{SHA: sha, Gate: gateCtx, Waited: time.Minute},
	} {
		if e.Error() == "" {
			t.Errorf("%T has an empty message", e)
		}
	}
	if (&GateTimeoutError{}).Unwrap() != nil {
		t.Error("a timeout with no last error unwraps to something")
	}
}

func TestFetchRefusesAnUnbuildableURL(t *testing.T) {
	err := fetch(host{client: http.DefaultClient}, "http://[::1]:namedport/", "token t", &giteaStatus{})
	var forgeErr *ForgeError
	if !errors.As(err, &forgeErr) || forgeErr.Err == nil {
		t.Fatalf("err = %v, want *ForgeError", err)
	}
}
