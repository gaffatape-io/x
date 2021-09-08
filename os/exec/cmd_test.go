package execx

import (
	"context"
	"testing"
)

func TestCommand(t *testing.T) {
	cmd := Command(context.TODO(), "rubberduck")
	stdout, err := cmd.Run()
	stderr, err := cmd.Stderr()
	
	t.Log(stdout, stderr, err)
}
