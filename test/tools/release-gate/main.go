// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Command release-gate refuses a release unless the tagged commit is on main
// and CI's gate passed for that exact commit. .github/workflows/release.yml
// runs it before anything is built or published:
//
//	go run ./test/tools/release-gate -sha <commit> -main-ref <ref> \
//	    -status-context 'CI / CI Gate (push)' -workflow ci.yml -job-name 'CI Gate'
//
// # Why
//
// A `v*` tag used to publish on its own: the release workflow ran on the tag
// push with no dependency on CI, so a tag on a commit whose CI was red, still
// running, canceled or never run published binaries all the same. The release
// commit and its tag are pushed together (`make release-alpha`), so CI for the
// commit is normally still running when this starts. This command therefore
// WAITS for the gate's result rather than reading it once, and refuses on
// anything but a pass.
//
// # What it reads
//
// On a self-hosted (Gitea) forge, the commit's combined status, for the
// context CI's gate job reports on a push to main -- the same signal the
// merge automation trusts. On github.com, the Actions API: the latest run of
// the CI workflow FILE for this commit with event=push on main, and that
// run's gate job. Not a check run looked up by name: a check run of the same
// name from a pull_request run, an older run or another app would otherwise
// count. Either way only "passed" lets the release through. A gate that failed, errored, was canceled or reported
// anything this command does not recognize stops it at once. A gate that
// reports nothing before the deadline also stops it.
//
// The token comes from FORGE_TOKEN in the environment, never from a flag, so
// it does not appear in a process listing.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/jeremyhahn/go-luks2/internal/clock"
)

// githubServer is the one server whose API is GitHub's rather than Gitea's.
const githubServer = "https://github.com"

// maxBody bounds what is read from the forge. A status page is a few KiB.
const maxBody = 4 << 20

var fullSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// request is one parsed command line.
type request struct {
	sha           string
	mainRef       string
	statusContext string
	workflow      string
	jobName       string
	timeout       time.Duration
	poll          time.Duration
}

// host is everything the gate touches outside itself, so every refusal can be
// driven by a test with no forge, no git and no wall clock.
type host struct {
	getenv func(key string) string
	// git runs git and returns its exit status; err is set only when git
	// could not be run at all.
	git    func(args ...string) (status int, output string, err error)
	client *http.Client
	clock  clock.Clock
}

func main() {
	os.Exit(cli(os.Args[1:], os.Stdout, os.Stderr, systemHost()))
}

// cli runs one invocation and returns the exit status: 0 releasable, 1 not.
func cli(args []string, stdout, stderr io.Writer, h host) int {
	req, err := parseArgs(args, stderr)
	if err == nil {
		err = gate(stdout, h, req)
	}
	if err != nil {
		fmt.Fprintln(stderr, "FAIL:", err)
		return 1
	}
	return 0
}

func systemHost() host {
	return host{
		getenv: os.Getenv,
		git: func(args ...string) (int, string, error) {
			// The arguments are a validated 40-hex commit and the workflow's
			// own ref name, not free text.
			out, err := exec.Command("git", args...).CombinedOutput() // #nosec G204 -- validated commit id and fixed ref
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				return exit.ExitCode(), string(out), nil
			}
			if err != nil {
				return -1, string(out), err
			}
			return 0, string(out), nil
		},
		client: &http.Client{Timeout: 30 * time.Second},
		clock:  clock.System{},
	}
}

func parseArgs(args []string, stderr io.Writer) (request, error) {
	fs := flag.NewFlagSet("release-gate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var req request
	fs.StringVar(&req.sha, "sha", "", "the tagged commit, 40 hex digits")
	fs.StringVar(&req.mainRef, "main-ref", "", "a ref naming main's tip, fetched before this runs")
	fs.StringVar(&req.statusContext, "status-context", "", "the commit-status context of CI's gate (Gitea)")
	fs.StringVar(&req.workflow, "workflow", "", "the CI workflow's file name under .github/workflows (github.com)")
	fs.StringVar(&req.jobName, "job-name", "", "the name of CI's gate job (github.com)")
	fs.DurationVar(&req.timeout, "timeout", 2*time.Hour, "how long to wait for the gate to report")
	fs.DurationVar(&req.poll, "poll", 30*time.Second, "how often to ask")
	if err := fs.Parse(args); err != nil {
		return request{}, &UsageError{Problem: err.Error()}
	}
	switch {
	case fs.NArg() != 0:
		return request{}, &UsageError{Problem: "unexpected arguments: " + strings.Join(fs.Args(), " ")}
	case !fullSHA.MatchString(req.sha):
		return request{}, &UsageError{Problem: fmt.Sprintf("-sha %q is not a full 40-hex commit id", req.sha)}
	case req.mainRef == "" || strings.HasPrefix(req.mainRef, "-"):
		return request{}, &UsageError{Problem: fmt.Sprintf("-main-ref %q is not a ref", req.mainRef)}
	case req.statusContext == "":
		return request{}, &UsageError{Problem: "missing -status-context"}
	case req.workflow == "" || strings.ContainsAny(req.workflow, "/?#&"):
		return request{}, &UsageError{Problem: fmt.Sprintf("-workflow %q is not a workflow file name", req.workflow)}
	case req.jobName == "":
		return request{}, &UsageError{Problem: "missing -job-name"}
	case req.timeout <= 0 || req.poll <= 0:
		return request{}, &UsageError{Problem: "-timeout and -poll must be positive"}
	}
	return req, nil
}

// gate is the decision: on main, then CI's gate passed.
func gate(out io.Writer, h host, req request) error {
	if err := onMain(h, req); err != nil {
		return err
	}
	fmt.Fprintf(out, "ok  %s is on main (%s)\n", req.sha, req.mainRef)

	read, name, err := gateReader(h, req)
	if err != nil {
		return err
	}
	if err := waitForGate(out, h, req, name, read); err != nil {
		return err
	}
	fmt.Fprintf(out, "ok  CI's gate %q passed for %s\n", name, req.sha)
	return nil
}

// onMain asks git whether sha is an ancestor of mainRef. Exit 0 is yes, 1 is
// no; anything else, or git not running at all, is no answer and refuses.
func onMain(h host, req request) error {
	status, output, err := h.git("merge-base", "--is-ancestor", req.sha, req.mainRef)
	switch {
	case err != nil:
		return &AncestryError{SHA: req.sha, MainRef: req.mainRef, Output: output, Err: err}
	case status == 0:
		return nil
	case status == 1:
		return &NotOnMainError{SHA: req.sha, MainRef: req.mainRef}
	default:
		return &AncestryError{SHA: req.sha, MainRef: req.mainRef, Output: output,
			Err: &ExitStatusError{Command: "git merge-base --is-ancestor", Status: status}}
	}
}

// gateState is one reading of the gate.
type gateState int

const (
	gatePending gateState = iota
	gatePassed
	gateFailed
)

// reader takes one reading: the state and, for a failure, what the forge said.
type reader func() (gateState, string, error)

// gateReader picks the forge's API from the environment the runner provides.
func gateReader(h host, req request) (reader, string, error) {
	server := strings.TrimSuffix(h.getenv("GITHUB_SERVER_URL"), "/")
	repo := h.getenv("GITHUB_REPOSITORY")
	token := h.getenv("FORGE_TOKEN")
	switch {
	case server == "":
		return nil, "", &UsageError{Problem: "GITHUB_SERVER_URL is not set; this runs inside a workflow"}
	case strings.Count(repo, "/") != 1:
		return nil, "", &UsageError{Problem: fmt.Sprintf("GITHUB_REPOSITORY %q is not owner/name", repo)}
	case token == "":
		return nil, "", &UsageError{Problem: "FORGE_TOKEN is not set; the gate's status cannot be read anonymously"}
	}

	if server == githubServer {
		api := strings.TrimSuffix(h.getenv("GITHUB_API_URL"), "/")
		if api == "" {
			api = "https://api.github.com"
		}
		return func() (gateState, string, error) {
			return readWorkflowJob(h, api, repo, "Bearer "+token, req)
		}, req.workflow + " / " + req.jobName, nil
	}

	base := fmt.Sprintf("%s/api/v1/repos/%s/commits/%s/status", server, repo, req.sha)
	return func() (gateState, string, error) {
		return readStatuses(h, base, "token "+token, req.statusContext)
	}, req.statusContext, nil
}

// waitForGate polls until the gate passes, fails, or the deadline expires.
func waitForGate(out io.Writer, h host, req request, name string, read reader) error {
	deadline := h.clock.Now().Add(req.timeout)
	var lastErr error
	for {
		state, detail, err := read()
		var transient *transientError
		switch {
		case errors.As(err, &transient):
			lastErr = err
			fmt.Fprintf(out, "..  could not read the gate yet (%v); retrying\n", err)
		case err != nil:
			return err
		case state == gatePassed:
			return nil
		case state == gateFailed:
			return &GateFailedError{SHA: req.sha, Gate: name, State: detail}
		default:
			lastErr = nil
			fmt.Fprintf(out, "..  CI's gate %q has not finished for %s; waiting\n", name, req.sha)
		}
		if !h.clock.Now().Before(deadline) {
			return &GateTimeoutError{SHA: req.sha, Gate: name, Waited: req.timeout, LastErr: lastErr}
		}
		<-h.clock.NewTimer(req.poll).C()
	}
}

// fetch GETs u and decodes a JSON body into v. A 5xx or an unanswered request
// is transient; any other non-200 is final.
func fetch(h host, u, auth string, v any) error {
	r, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return &ForgeError{URL: u, Err: err}
	}
	r.Header.Set("Authorization", auth)
	r.Header.Set("Accept", "application/json")
	resp, err := h.client.Do(r)
	if err != nil {
		return &transientError{URL: u, Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return &transientError{URL: u, Err: err}
	}
	switch {
	case resp.StatusCode >= 500:
		return &transientError{URL: u, Err: &HTTPStatusError{Status: resp.StatusCode}}
	case resp.StatusCode != http.StatusOK:
		return &ForgeError{URL: u, Status: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	}
	if err := json.Unmarshal(body, v); err != nil {
		return &ForgeError{URL: u, Status: resp.StatusCode, Err: err}
	}
	return nil
}

// giteaStatus is the part of Gitea's combined status this reads. Gitea reports
// the LATEST status per context, so a re-run that passed replaces the failure
// it re-ran.
type giteaStatus struct {
	TotalCount int `json:"total_count"`
	Statuses   []struct {
		Context string `json:"context"`
		Status  string `json:"status"`
	} `json:"statuses"`
}

// readStatuses pages the commit's combined status for context.
func readStatuses(h host, base, auth, context string) (gateState, string, error) {
	seen := 0
	for page := 1; ; page++ {
		var s giteaStatus
		u := fmt.Sprintf("%s?limit=50&page=%d", base, page)
		if err := fetch(h, u, auth, &s); err != nil {
			return gatePending, "", err
		}
		for _, st := range s.Statuses {
			if st.Context != context {
				continue
			}
			switch st.Status {
			case "success":
				return gatePassed, st.Status, nil
			case "pending":
				return gatePending, st.Status, nil
			default:
				// failure, error, warning, or a state added later: none of
				// them is a pass, and none of them will turn into one by
				// waiting.
				return gateFailed, st.Status, nil
			}
		}
		seen += len(s.Statuses)
		if len(s.Statuses) == 0 || seen >= s.TotalCount {
			// Not reported yet: CI has not reached the gate job.
			return gatePending, "", nil
		}
	}
}

// githubRuns is the part of GitHub's workflow-runs listing this reads.
type githubRuns struct {
	WorkflowRuns []struct {
		ID         int64  `json:"id"`
		HeadSHA    string `json:"head_sha"`
		Event      string `json:"event"`
		HeadBranch string `json:"head_branch"`
		Status     string `json:"status"`
		Conclusion string `json:"conclusion"`
	} `json:"workflow_runs"`
}

// githubJobs is the part of GitHub's jobs listing this reads.
type githubJobs struct {
	Jobs []struct {
		Name       string `json:"name"`
		Status     string `json:"status"`
		Conclusion string `json:"conclusion"`
	} `json:"jobs"`
}

// readWorkflowJob reads the gate job of the latest push-to-main run of the CI
// workflow for the commit. The listing is filtered server-side and every
// field is checked again here: a run that is not this commit's push to main
// is never the evidence.
func readWorkflowJob(h host, api, repo, auth string, req request) (gateState, string, error) {
	var runs githubRuns
	u := fmt.Sprintf("%s/repos/%s/actions/workflows/%s/runs?head_sha=%s&event=push&branch=main&per_page=100",
		api, repo, url.PathEscape(req.workflow), req.sha)
	if err := fetch(h, u, auth, &runs); err != nil {
		return gatePending, "", err
	}
	var latest int64
	var runStatus, runConclusion string
	for _, r := range runs.WorkflowRuns {
		if r.HeadSHA == req.sha && r.Event == "push" && r.HeadBranch == "main" && r.ID > latest {
			latest, runStatus, runConclusion = r.ID, r.Status, r.Conclusion
		}
	}
	if latest == 0 {
		// CI has not started for this push yet.
		return gatePending, "", nil
	}

	// filter=latest: the jobs of the run's latest ATTEMPT, so a re-run that
	// passed replaces the attempt it re-ran.
	var jobs githubJobs
	u = fmt.Sprintf("%s/repos/%s/actions/runs/%d/jobs?filter=latest&per_page=100", api, repo, latest)
	if err := fetch(h, u, auth, &jobs); err != nil {
		return gatePending, "", err
	}
	for _, j := range jobs.Jobs {
		if j.Name != req.jobName {
			continue
		}
		switch {
		case j.Status != "completed":
			return gatePending, j.Status, nil
		case j.Conclusion == "success":
			return gatePassed, j.Conclusion, nil
		default:
			return gateFailed, j.Conclusion, nil
		}
	}
	// No gate job. While the run is going it has not been created yet -- it
	// waits on every other job. Once the run is over it never will be.
	if runStatus == "completed" {
		return gateFailed, "run " + runConclusion + " without a " + req.jobName + " job", nil
	}
	return gatePending, "", nil
}
