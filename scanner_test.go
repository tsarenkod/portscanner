package portscan

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestNewOptions(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if scanner.config.concurrency != defaultConcurrency || scanner.config.connectTimeout != defaultConnectTimeout {
		t.Fatalf("defaults = (%d, %s), want (%d, %s)", scanner.config.concurrency, scanner.config.connectTimeout, defaultConcurrency, defaultConnectTimeout)
	}

	scanner, err = New(WithConcurrency(3), WithConnectTimeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if scanner.config.concurrency != 3 || scanner.config.connectTimeout != time.Second {
		t.Fatalf("configured values = (%d, %s), want (3, 1s)", scanner.config.concurrency, scanner.config.connectTimeout)
	}

	for name, options := range map[string][]Option{
		"nil option":           {nil},
		"zero concurrency":     {WithConcurrency(0)},
		"negative concurrency": {WithConcurrency(-1)},
		"zero timeout":         {WithConnectTimeout(0)},
		"negative timeout":     {WithConnectTimeout(-time.Second)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(options...); err == nil {
				t.Fatal("New() error = nil, want error")
			}
		})
	}
}

func TestScanValidation(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatal(err)
	}
	ports, err := Ports(80)
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	for name, test := range map[string]struct {
		scanner *Scanner
		ctx     context.Context
		hosts   []string
		ports   PortSet
	}{
		"nil scanner":      {nil, context.Background(), []string{"127.0.0.1"}, ports},
		"nil context":      {scanner, nil, []string{"127.0.0.1"}, ports},
		"canceled context": {scanner, canceled, []string{"127.0.0.1"}, ports},
		"no hosts":         {scanner, context.Background(), nil, ports},
		"no ports":         {scanner, context.Background(), []string{"127.0.0.1"}, PortSet{}},
		"invalid host":     {scanner, context.Background(), []string{"bad host"}, ports},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := test.scanner.Scan(test.ctx, test.hosts, test.ports); err == nil {
				t.Fatal("Scan() error = nil, want error")
			}
		})
	}
}

func TestScanCancellationClosesResults(t *testing.T) {
	scanner, err := New(WithConcurrency(2))
	if err != nil {
		t.Fatal(err)
	}
	ports, err := Range(1, 65535)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, ports)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	collectResults(t, results)
}

func TestScanSlowConsumer(t *testing.T) {
	scanner, err := New(WithConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	ports, err := Range(1, 32)
	if err != nil {
		t.Fatal(err)
	}
	results, err := scanner.Scan(context.Background(), []string{"127.0.0.1"}, ports)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if got := collectResults(t, results); len(got) != 32 {
		t.Fatalf("Scan() returned %d results after backpressure, want 32", len(got))
	}
}

func startTCP4Listener(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	return listener
}

func reserveClosedTCP4Port(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func collectResults(t *testing.T, results <-chan Result) []Result {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	var collected []Result
	for {
		select {
		case result, ok := <-results:
			if !ok {
				return collected
			}
			collected = append(collected, result)
		case <-timer.C:
			t.Fatal("timed out waiting for results channel to close")
			return nil
		}
	}
}
