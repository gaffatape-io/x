package nmap

import (
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseScanPortsOutput(t *testing.T) {
	tests := []struct {
		inputFile string
		result ScanResult
	} {
		{
			"scanme_nmap_org_output.txt",
			ScanResult{
				StartedAt: time.Date(2021, 9, 7, 12, 29, 0, 0, time.Local),
				Reports: map[string]ScanReport{
					"scanme.nmap.org": {
						ID: "scanme.nmap.org",
						ID2: "45.33.32.156",
						Ports: []PortReport{
							{"22/tcp", "open", "ssh"},
							{"80/tcp", "open", "http"},
							{"9929/tcp", "open", "nping-echo"},
							{"31337/tcp", "open", "Elite"},
						},
					},
				},
				Duration: 31 * time.Second + 760 * time.Millisecond,
			},
		},
		{
			"iprange_output.txt",
			ScanResult{
				StartedAt: time.Date(2021, 9, 8, 15, 59, 0, 0, time.Local),
				Reports: map[string]ScanReport{
					"static-90-139-102-193.tele2.se": {
						ID: "static-90-139-102-193.tele2.se",
						ID2: "90.139.102.193",
						Ports: []PortReport{
							{"80/tcp", "open", "http"},
							{"443/tcp", "open", "https"},
						},
					},
					"static-90-139-102-194.tele2.se": {
						ID: "static-90-139-102-194.tele2.se",
						ID2: "90.139.102.194",
						Ports: []PortReport{
							{"80/tcp", "open", "http"},
							{"443/tcp", "open", "https"},
						},
					},
					"static-90-139-102-195.tele2.se": {
						ID: "static-90-139-102-195.tele2.se",
						ID2: "90.139.102.195",
						Ports: []PortReport{
							{"80/tcp", "open", "http"},
							{"443/tcp", "open", "https"},
						},
					},
					"static-90-139-102-196.tele2.se": {
						ID: "static-90-139-102-196.tele2.se",
						ID2: "90.139.102.196",
						Ports: []PortReport{
							{"80/tcp", "open", "http"},
							{"443/tcp", "open", "https"},
						},
					},
				},
				Duration: 10 * time.Second + 10 * time.Millisecond,
			},
		},
	}

	for _, tc := range tests {
		b := &strings.Builder{}
		
		input, err := os.Open(tc.inputFile)
		if err != nil {
			t.Fatal(err)
		}
		defer input.Close()

		res, err := parseScanPortsOutput(io.TeeReader(input, b))
		t.Log("tee:ed input:\n", b)
		if err != nil {
			t.Fatal(err)
		}

		t.Log(res)

		if !reflect.DeepEqual(res, tc.result) {
			t.Fatal(tc.result)
		}
	}
}

type scanPortsTest struct {
	target      string
	is6         bool
	reportCount int
}

var (
	scanPortsTests = []scanPortsTest {
		{"localhost", false, 1},
		{"::1", true, 1},
		{"malformed\\..\t.host", false, 0},
		{"malformed\\..\t.host", true, 0},
	}
)

func checkScanPortsResult(t *testing.T, res ScanResult, err error, tc scanPortsTest) {
	t.Log(res)
	if err != nil {
		t.Error(err)
	}
	
	if len(res.Reports) != tc.reportCount {
		t.Errorf("wrong # of reports in result; reportCount:%v", len(res.Reports))
	}
}

func TestScanPorts(t *testing.T) {
	for _, tc := range scanPortsTests {
		t.Logf("--- test case: %+v", tc)
		res, err := ScanPorts(TargetSpec(tc.target), tc.is6)
		checkScanPortsResult(t, res, err, tc)
	}
}
