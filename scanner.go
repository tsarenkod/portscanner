// Package portscan предоставляет потоковый TCP Connect-сканер.
package portscan

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// State описывает результат одной попытки TCP-подключения.
type State string

const (
	StateOpen        State = "open"        // соединение установлено
	StateClosed      State = "closed"      // удаленная сторона отказала в соединении
	StateTimeout     State = "timeout"     // истек таймаут попытки подключения
	StateUnreachable State = "unreachable" // сеть или узел недоступны
	StateCanceled    State = "canceled"    // контекст сканирования отменён
	StateError       State = "error"       // произошла другая ошибка

	defaultConcurrency    = 100                    // параллелизм сканера по умолчанию
	defaultConnectTimeout = 500 * time.Millisecond // таймаут подключения по умолчанию
)

// Result содержит результат проверки одного порта на одном IP-адресе.
type Result struct {
	Host     string        // Исходная цель после удаления внешних пробелов.
	IP       net.IP        // Проверенный адрес; nil при ошибке DNS.
	Port     uint16        // Проверенный TCP-порт.
	State    State         // Итоговое состояние подключения.
	Duration time.Duration // Время подключения или DNS-разрешения.
	Err      error         // Исходная ошибка; nil при успешном подключении.
}

// config хранит неизменяемые настройки экземпляра сканера.
type config struct {
	concurrency    int
	connectTimeout time.Duration
}

// Option изменяет настройки сканера при вызове New.
type Option func(*config) error

// Scanner выполняет параллельную проверку TCP-портов.
type Scanner struct {
	config config
}

// New создаёт сканер с настройками по умолчанию и применяет переданные опции.
func New(options ...Option) (*Scanner, error) {
	cfg := config{
		concurrency:    defaultConcurrency,
		connectTimeout: defaultConnectTimeout,
	}
	for _, option := range options {
		if option == nil {
			return nil, errors.New("nil scanner option")
		}
		if err := option(&cfg); err != nil {
			return nil, err
		}
	}
	return &Scanner{config: cfg}, nil
}

// WithConcurrency задаёт положительный лимит одновременных подключений.
func WithConcurrency(n int) Option {
	return func(cfg *config) error {
		if n <= 0 {
			return errors.New("concurrency must be positive")
		}
		cfg.concurrency = n
		return nil
	}
}

// WithConnectTimeout задаёт положительный таймаут одной попытки подключения.
func WithConnectTimeout(d time.Duration) Option {
	return func(cfg *config) error {
		if d <= 0 {
			return errors.New("connect timeout must be positive")
		}
		cfg.connectTimeout = d
		return nil
	}
}

// Scan проверяет цели и порты, затем возвращает канал потоковых результатов.
// Ошибки аргументов возвращаются сразу; ошибки DNS и подключений приходят в Result.
func (s *Scanner) Scan(ctx context.Context, hosts []string, ports PortSet) (<-chan Result, error) {
	if s == nil {
		return nil, errors.New("nil scanner")
	}
	if ctx == nil {
		return nil, errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		return nil, errors.New("at least one host is required")
	}
	if len(ports.ports) == 0 {
		return nil, errors.New("at least one port is required")
	}
	targets, err := normalizeHosts(hosts)
	if err != nil {
		return nil, err
	}

	jobs := make(chan job, s.config.concurrency)
	results := make(chan Result, s.config.concurrency)
	var workers sync.WaitGroup
	workers.Add(s.config.concurrency)

	for range s.config.concurrency {
		go func() {
			defer workers.Done()
			s.worker(ctx, jobs, results)
		}()
	}
	go func() {
		defer close(jobs)
		for _, target := range targets {
			if ctx.Err() != nil {
				return
			}
			if target.ip != nil {
				if !sendJobs(ctx, jobs, target.host, target.ip, ports.ports) {
					return
				}
				continue
			}
			s.scanName(ctx, target, ports.ports, jobs, results)
		}
	}()
	go func() {
		workers.Wait()
		close(results)
	}()
	return results, nil
}
