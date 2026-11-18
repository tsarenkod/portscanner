package portscan

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
)

func TestClassifyError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	timeout := &testTimeoutError{}

	for name, test := range map[string]struct {
		ctx  context.Context
		err  error
		want State
	}{
		"canceled context":            {ctx, errors.New("any error"), StateCanceled},
		"refused":                     {context.Background(), syscall.ECONNREFUSED, StateClosed},
		"Winsock refused":             {context.Background(), wsaECONNREFUSED, StateClosed},
		"network unreachable":         {context.Background(), syscall.ENETUNREACH, StateUnreachable},
		"Winsock network unreachable": {context.Background(), wsaENETUNREACH, StateUnreachable},
		"host unreachable":            {context.Background(), syscall.EHOSTUNREACH, StateUnreachable},
		"Winsock host unreachable":    {context.Background(), wsaEHOSTUNREACH, StateUnreachable},
		"deadline":                    {context.Background(), context.DeadlineExceeded, StateTimeout},
		"net timeout":                 {context.Background(), timeout, StateTimeout},
		"other":                       {context.Background(), errors.New("failure"), StateError},
	} {
		t.Run(name, func(t *testing.T) {
			if got := classifyError(test.ctx, test.err); got != test.want {
				t.Fatalf("classifyError() = %q, want %q", got, test.want)
			}
		})
	}
}

type testTimeoutError struct{}

func (*testTimeoutError) Error() string   { return "timeout" }
func (*testTimeoutError) Timeout() bool   { return true }
func (*testTimeoutError) Temporary() bool { return true }

func TestScanOpenClosedAndReuse(t *testing.T) {
	listener := startTCP4Listener(t)
	openPort := listener.Addr().(*net.TCPAddr).Port
	closedPort := reserveClosedTCP4Port(t)
	ports, err := Ports(openPort, closedPort)
	if err != nil {
		t.Fatal(err)
	}
	scanner, err := New(WithConcurrency(2))
	if err != nil {
		t.Fatal(err)
	}

	for run := 0; run < 2; run++ {
		results, err := scanner.Scan(context.Background(), []string{"127.0.0.1"}, ports)
		if err != nil {
			t.Fatal(err)
		}
		got := collectResults(t, results)
		if len(got) != 2 {
			t.Fatalf("Scan() returned %d results, want 2: %#v", len(got), got)
		}
		states := make(map[uint16]State, len(got))
		failures := make(map[uint16]error)
		for _, result := range got {
			states[result.Port] = result.State
			failures[result.Port] = result.Err
			if result.Host != "127.0.0.1" || result.IP.String() != "127.0.0.1" {
				t.Errorf("result target = (%q, %v), want (127.0.0.1, 127.0.0.1)", result.Host, result.IP)
			}
			if result.Duration < 0 {
				t.Errorf("negative duration: %s", result.Duration)
			}
		}
		if states[uint16(openPort)] != StateOpen || states[uint16(closedPort)] != StateClosed {
			t.Fatalf("result states = %v, errors = %v, want open on %d and closed on %d", states, failures, openPort, closedPort)
		}
	}
}
