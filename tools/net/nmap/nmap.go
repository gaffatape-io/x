//go:generate protoc --go_out=../../../../../.. nmap.proto

package nmap

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"time"
	"strconv"
	"strings"

	"github.com/gaffatape-io/gopherrs"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TargetSpec type matches the nmap {target specification} format.
type TargetSpec string

func scanLine(s *bufio.Scanner) (string, bool) {
	if !s.Scan() {
		return "", false
	}

	return s.Text(), true
}

func scanStartedAt(s *bufio.Scanner, r *ScanResult) error {
	l, ok := scanLine(s)
	if !ok {
		return gopherrs.InvalidArgument("started at header missing")
	}

	at := strings.LastIndex(l, "at ")
	if at < 0 {
		return gopherrs.InvalidArgument("started at header malformed")
	}

	startedAt, err := time.Parse("2006-01-02 15:04 MST", l[at+3:])
	r.StartedAt = timestamppb.New(startedAt)
	return err
}

func splitHostIDs(l string) (string, string) {
	prefixLen := len("Nmap scan report for")
	suffixAt := strings.LastIndexByte(l, '(')
	id := l[prefixLen+1:suffixAt-1]
	id2 := l[suffixAt+1:len(l)-1]
	return id, id2
}

func scanReportLine(l string) (*PortReport, error) {
	report := &PortReport{}
	parts := strings.Split(l, " ")
	at := 0
	for _, p := range parts {
		if len(p) == 0 {
			continue
		}

		switch at {
		case 0:
			report.Port = p
			at++

		case 1:
			report.State = p
			at++

		case 2:
			report.Service = p
			return report, nil
		}
	}

	return nil, gopherrs.InvalidArgumentf("malformed port line; %q", l)
}

func scanPorts(s *bufio.Scanner) ([]*PortReport, error) {
	ports := []*PortReport{}

	// skip all lines until we find the PORT/STATE/SERVICE table header
	for {
		l, ok := scanLine(s)
		if !ok {
			return nil, gopherrs.InvalidArgument("header scan failure; malformed input?")
		}

		if strings.HasPrefix(l, "PORT") {
			break
		}
	}

	// scan line by line until we find an empty line
	for {
		l, ok := scanLine(s)
		if !ok {
			return nil, gopherrs.InvalidArgument("port scan failure; malformed input?")
		}

		if len(l) == 0 {
			return ports, nil
		}

		port, err := scanReportLine(l)
		if err != nil {
			return nil, err
		}
		
		ports = append(ports, port)
	}
}

// parseDuration parses the duration string from nmap into a time.Duration.
// The expected format is ss.hundreds.
func parseDuration(txt string) (time.Duration, error) {
	const sep = "."
	sepAt := strings.Index(txt, sep)
	if sepAt < 0 {
		return 0, gopherrs.InvalidArgumentf("failed to find separator: %q", txt)
	}

	secondsTxt := txt[:sepAt]
	hundredsTxt := txt[sepAt+1:]

	seconds, err := strconv.Atoi(secondsTxt)
	if err != nil {
		return 0, gopherrs.WrapInvalidArgumentf(err, "failed to parse duration: %q", secondsTxt)
	}

	millis, err := strconv.Atoi(hundredsTxt)
	if err != nil {
		return 0, gopherrs.WrapInvalidArgumentf(err, "failed to parse duration: %q", hundredsTxt)
	}

	millis *= 10
	return time.Duration(seconds) * time.Second + time.Duration(millis) * time.Millisecond, nil
}

// scanReports scans all report entries (one per host with one line per port)
func scanReports(s *bufio.Scanner, r *ScanResult) error {	
	for {
		l, ok := scanLine(s)
		if !ok {
			return gopherrs.InvalidArgument("scan failed; malformed input?")
		}

		fmt.Println(">", l)
		
		if strings.HasPrefix(l, "Nmap scan report for") {
			id, id2 := splitHostIDs(l)
		
			report := &ScanReport{Id: id, Id2: id2}
			var err error
			report.Ports, err = scanPorts(s)
			if err != nil {
				return err
			}

			if r.Reports == nil {
				r.Reports = map[string]*ScanReport{}
			}
		
			r.Reports[id] = report
		} else if strings.HasPrefix(l, "Nmap done:") {
			const sep = " in "
			inAt := strings.LastIndex(l, sep)
			if inAt < 0 {
				return gopherrs.InvalidArgumentf("unable to find separator: %q", l)
			}

			const suffix = " seconds"
			if !strings.HasSuffix(l, suffix) {
				return gopherrs.InvalidArgumentf("failed to find suffix: %q %q", suffix, l)
			}

			durationTxt := l[inAt + len(sep):len(l)-len(suffix)]
			duration, err := parseDuration(durationTxt)
			if err != nil {
				return err
			}
			r.Duration = durationpb.New(duration)
			return nil
		} else {
			return gopherrs.InvalidArgumentf("unexpected input: %q", l)
		}
	}
}

func scanDuration(s *bufio.Scanner, r *ScanResult) error {
	return nil
}

func parseScanPortsOutput(r io.Reader) (*ScanResult, error) {
	res := &ScanResult{}
	log := &bytes.Buffer{}
	scanner := bufio.NewScanner(io.TeeReader(r, log))

	ops := []func(*bufio.Scanner, *ScanResult) error {
		scanStartedAt,
		scanReports,
		scanDuration,	
	}

	for _, op := range ops {
		err := op(scanner, res)
		if err != nil {
			// TODO(dape): replace with some proper logging
			fmt.Println("parsed:", log.String())
			return nil, err
		}
	}

	return res, nil
}

func ScanPorts(targets TargetSpec, is6 bool) (*ScanResult, error) {
	args := []string{string(targets)}
	if is6 {
		args = append(args, "-6")
	}
	cmd := exec.Command("nmap", args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, gopherrs.WrapUnknown(err, "StdoutPipe() failed")
	}

	err = cmd.Start()
	if err != nil {
		return nil, gopherrs.WrapUnknown(err, "Start() failed")
	}
	
	result, err := parseScanPortsOutput(stdout)
	if err != nil {
		return nil, err
	}

	// If we got here then the parser finished; most likely the command should
	// also have finished successfully but we add a check here to be safe.
	err = cmd.Wait()
	if err != nil {
		return nil, gopherrs.WrapUnknown(err, "Wait() failed")
	}

	return result, err
}
