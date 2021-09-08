package execx

import (
	"context"
	"io"
	"os/exec"

	"github.com/gaffatape-io/gopherrs"
)

type Cmd interface {
	// Runs the command and returns a reader for stdout.
	Run() (io.Reader, error)

	// Returns the io.Reader for Stderr; can only be called once Run have completed.
	Stderr() (io.Reader, error)
}

type cmd struct {
	*exec.Cmd
	stderr io.Reader
}

func (c *cmd) Run() (io.Reader, error) {
	if c.stderr != nil {
		return nil, gopherrs.FailedPrecondition("Run() alread called")
	}
	
	stdout, err := c.StdoutPipe()
	if err != nil {
		return nil, gopherrs.WrapFailedPrecondition(err, "StdoutPipe() failed")
	}

	c.stderr, err = c.StderrPipe()
	if err != nil {
		return nil, gopherrs.WrapFailedPrecondition(err, "StderrPipe() failed")
	}

	err = c.Cmd.Run()
	if err != nil {	
	}
	
	return stdout, err
}

func (c *cmd) Stderr() (io.Reader, error) {
	if c.stderr == nil {
		return nil, gopherrs.FailedPrecondition("Run() not called")
	}

	return c.stderr, nil
}

func Command(ctx context.Context, name string, arg ...string) Cmd {
	c := &cmd{exec.CommandContext(ctx, name, arg...), nil}
	return c
}

