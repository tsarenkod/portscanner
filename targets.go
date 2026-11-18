package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// target хранит очищенную цель и её канонический IP, если цель является IP-литералом.
type target struct {
	host string
	ip   net.IP
}

// normalizeHosts проверяет, нормализует и дедуплицирует цели.
func normalizeHosts(hosts []string) ([]target, error) {
	seen := make(map[string]struct{}, len(hosts))
	targets := make([]target, 0, len(hosts))
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			return nil, errors.New("host must not be empty")
		}
		if ip := net.ParseIP(host); ip != nil {
			if ipv4 := ip.To4(); ipv4 != nil {
				ip = ipv4
			}
			key := "ip:" + ip.String()
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				targets = append(targets, target{host: host, ip: ip})
			}
			continue
		}
		if !validDNSName(host) {
			return nil, fmt.Errorf("invalid host %q", host)
		}
		key := "dns:" + strings.ToLower(strings.TrimSuffix(host, "."))
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			targets = append(targets, target{host: host})
		}
	}
	return targets, nil
}

// validDNSName проверяет ASCII-имя DNS с необязательной завершающей точкой.
func validDNSName(name string) bool {
	name = strings.TrimSuffix(name, ".")
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-') {
				return false
			}
		}
	}
	return true
}

// scanName разрешает DNS-имя и отправляет найденные адреса на проверку.
func (s *Scanner) scanName(ctx context.Context, target target, ports []uint16, jobs chan<- job, results chan<- Result) {
	started := time.Now()
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, target.host)
	duration := time.Since(started)
	if err != nil {
		wrapped := fmt.Errorf("resolve %q: %w", target.host, err)
		state := classifyError(ctx, err)
		for _, port := range ports {
			select {
			case results <- Result{Host: target.host, Port: port, State: state, Duration: duration, Err: wrapped}:
			case <-ctx.Done():
				return
			}
		}
		return
	}

	seen := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		ip := address.IP
		if ipv4 := ip.To4(); ipv4 != nil {
			ip = ipv4
		} else if ip = ip.To16(); ip == nil {
			continue
		}
		key := ip.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if !sendJobs(ctx, jobs, target.host, ip, ports) {
			return
		}
	}
	if len(seen) == 0 && ctx.Err() == nil {
		err := errors.New("DNS returned no IP addresses")
		for _, port := range ports {
			select {
			case results <- Result{Host: target.host, Port: port, State: StateError, Duration: duration, Err: fmt.Errorf("resolve %q: %w", target.host, err)}:
			case <-ctx.Done():
				return
			}
		}
	}
}

// sendJobs передаёт задания в очередь, прекращая отправку при отмене контекста.
func sendJobs(ctx context.Context, jobs chan<- job, host string, ip net.IP, ports []uint16) bool {
	for _, port := range ports {
		select {
		case jobs <- job{host: host, ip: ip, port: port}:
		case <-ctx.Done():
			return false
		}
	}
	return true
}
