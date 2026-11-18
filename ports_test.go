package portscan

import (
	"fmt"
	"reflect"
	"testing"
)

func TestPortSetConstructors(t *testing.T) {
	ports, err := Ports(80, 443, 80, 1)
	if err != nil {
		t.Fatal(err)
	}
	if want := []uint16{80, 443, 1}; !reflect.DeepEqual(ports.ports, want) {
		t.Fatalf("Ports() = %v, want %v", ports.ports, want)
	}

	for _, port := range []int{-1, 0, 65536} {
		t.Run(fmt.Sprintf("invalid port %d", port), func(t *testing.T) {
			if _, err := Ports(port); err == nil {
				t.Fatal("Ports() error = nil, want error")
			}
		})
	}
	if empty, err := Ports(); err != nil || len(empty.ports) != 0 {
		t.Fatalf("Ports() = (%v, %v), want empty set and nil error", empty.ports, err)
	}

	ports, err = Range(65534, 65535)
	if err != nil {
		t.Fatal(err)
	}
	if want := []uint16{65534, 65535}; !reflect.DeepEqual(ports.ports, want) {
		t.Fatalf("Range() = %v, want %v", ports.ports, want)
	}
	for _, bounds := range [][2]int{{0, 1}, {1, 65536}, {2, 1}, {-1, 65536}} {
		t.Run(fmt.Sprintf("invalid range %d..%d", bounds[0], bounds[1]), func(t *testing.T) {
			if _, err := Range(bounds[0], bounds[1]); err == nil {
				t.Fatal("Range() error = nil, want error")
			}
		})
	}

	combined := Combine(ports, PortSet{}, PortSet{ports: []uint16{65535, 22}})
	if want := []uint16{65534, 65535, 22}; !reflect.DeepEqual(combined.ports, want) {
		t.Fatalf("Combine() = %v, want %v", combined.ports, want)
	}
}
