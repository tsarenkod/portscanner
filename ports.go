package portscan

import "fmt"

// PortSet хранит упорядоченный набор TCP-портов.
type PortSet struct {
	ports []uint16
}

// Ports создаёт набор портов 1..65535, удаляя повторы с сохранением порядка.
func Ports(ports ...int) (PortSet, error) {
	set := PortSet{ports: make([]uint16, 0, len(ports))}
	seen := make(map[uint16]struct{}, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return PortSet{}, fmt.Errorf("port %d is outside 1..65535", port)
		}
		value := uint16(port)
		if _, ok := seen[value]; !ok {
			seen[value] = struct{}{}
			set.ports = append(set.ports, value)
		}
	}
	return set, nil
}

// Range создаёт включительный диапазон портов от from до to.
func Range(from, to int) (PortSet, error) {
	if from < 1 || to > 65535 || from > to {
		return PortSet{}, fmt.Errorf("invalid port range %d..%d", from, to)
	}
	ports := make([]uint16, 0, to-from+1)
	for port := from; port <= to; port++ {
		ports = append(ports, uint16(port))
	}
	return PortSet{ports: ports}, nil
}

// Combine объединяет наборы, сохраняя порядок первого появления портов.
func Combine(sets ...PortSet) PortSet {
	var combined PortSet
	seen := make(map[uint16]struct{})
	for _, set := range sets {
		for _, port := range set.ports {
			if _, ok := seen[port]; !ok {
				seen[port] = struct{}{}
				combined.ports = append(combined.ports, port)
			}
		}
	}
	return combined
}
