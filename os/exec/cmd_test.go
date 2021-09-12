package exec

import (
	"errors"
	"os/exec"
	"testing"

	rdt "github.com/gaffatape-io/rubberduck/testing"
)

func TestDispatch(t *testing.T) {
	tests := []struct {
		desc         string
		bin          string
		env          []string
		successCalls int
		successErr   error
		failureCalls int
		failureErr   error
	} {
		{
			"ok",
			rdt.FindBinary(t),
			nil,	
			1,
			nil,
			0,
			nil,
		},
		{
			"command found but return non-zero status",
			rdt.FindBinary(t),
			[]string{"RUBBERDUCK_STATUS=123"},
			0,
			nil,
			1,
			nil,
		},
		{
			"command not found",
			"no-such-binary",
			nil,
			0,
			nil,
			1,
			nil,
		},
		{
			"success handler failed, call failure handler?",
			rdt.FindBinary(t),
			nil,
			1,
			errors.New("should trigger failure handler"),
			1,
			nil,
		},
		{
			"success handler failed, check result from failure handler",
			rdt.FindBinary(t),
			nil,
			1,
			errors.New("should trigger failure handler"),
			1,
			errors.New("should be the returned error"),
		},				
	}

	for _, tc := range tests {
		t.Log("---", tc)
		cmd := exec.Command(tc.bin)
		if tc.env != nil {
			cmd.Env = tc.env
		}

		successCalls := 0
		failureCalls := 0

		// For this test we only check that the right function
		// is called the right number of times depending on the
		// outcome of the command.
		err := Dispatch(cmd,
			func (c *exec.Cmd) error {
				successCalls++
				return tc.successErr
			},
			func (err error, status int, c *exec.Cmd) error {
				failureCalls++
				return tc.failureErr
			})

		t.Log("dispatch error:", err)
		t.Log("status code:", cmd.ProcessState.ExitCode())

		if successCalls != tc.successCalls || failureCalls != tc.failureCalls {
			t.Fatal("wrong # of calls to success or failure", successCalls, failureCalls)
		}

		if tc.failureErr != nil && err != tc.failureErr {
			t.Fatal("the final error should be the return value from the failure handler")
		}
	}
}

func TestDispatchNoFailureHandler(t *testing.T) {
	err := Dispatch(exec.Command("no-such-binary"),
		func(*exec.Cmd) error {
			return nil
		},
		nil)

	t.Log(err)
	if err == nil {
		t.Fatal()
	}
}

func TestDispatchNoSuccessHandler(t *testing.T) {
	err := Dispatch(exec.Command(rdt.FindBinary(t)),
		nil,
		func(error, int, *exec.Cmd) error {
			return errors.New("should never be returned")
		})

	t.Log(err)
	if err != nil {
		t.Fatal()
	}
}
