package exec

import (
	. "os/exec"
)

// Using external commands always look the same:
// - create command
// - execute command
// - check error
// - iff error == nil => extract information from stdout
// - else => extract information from stderr
//
// When wrapping a binary/command as a function I want to test the individual
// pieces but I don't want to write the start/run/wait dispatching code.
//
func Dispatch(cmd *Cmd, success func(c *Cmd) error, failure func(err error, status int, c *Cmd) error) error {
	err := cmd.Run()
	if err == nil && success != nil {
		err = success(cmd)
	}

	if err != nil && failure != nil {
		err = failure(err, cmd.ProcessState.ExitCode(), cmd)
	}
	
	return err
}
