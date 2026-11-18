package portscan

import (
	"context"
	"errors"
	"net"
	"strconv"
	"syscall"
	"time"
)

const (
	wsaENETUNREACH  syscall.Errno = 10051 // Windows: сеть недоступна.
	wsaECONNREFUSED syscall.Errno = 10061 // Windows: соединение отклонено.
	wsaEHOSTUNREACH syscall.Errno = 10065 // Windows: узел недоступен.
)

// job описывает одну попытку подключения к адресу и порту.
type job struct {
	host string
	ip   net.IP
	port uint16
}

// worker обрабатывает задания и публикует результаты до закрытия очереди или отмены.
func (s *Scanner) worker(ctx context.Context, jobs <-chan job, results chan<- Result) {
	for {
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case task, ok := <-jobs:
			if !ok {
				return
			}
			result := s.connect(ctx, task)
			select {
			case results <- result:
			case <-ctx.Done():
				return
			}
		}
	}
}

// connect выполняет TCP-подключение с настроенным таймаутом и формирует результат.
func (s *Scanner) connect(ctx context.Context, task job) Result {
	result := Result{Host: task.host, IP: append(net.IP(nil), task.ip...), Port: task.port}
	connectCtx, cancel := context.WithTimeout(ctx, s.config.connectTimeout)
	defer cancel()

	started := time.Now()
	connection, err := (&net.Dialer{}).DialContext(connectCtx, "tcp", net.JoinHostPort(task.ip.String(), strconv.Itoa(int(task.port))))
	result.Duration = time.Since(started)
	if err == nil {
		result.State = StateOpen
		_ = connection.Close()
		return result
	}
	result.Err = err
	result.State = classifyError(ctx, err)
	return result
}

// classifyError сопоставляет сетевую ошибку с публичным состоянием результата.
func classifyError(ctx context.Context, err error) State {
	if ctx.Err() != nil {
		return StateCanceled
	}
	switch {
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, wsaECONNREFUSED):
		return StateClosed
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH),
		errors.Is(err, wsaENETUNREACH), errors.Is(err, wsaEHOSTUNREACH):
		return StateUnreachable
	}
	var networkError net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &networkError) && networkError.Timeout() {
		return StateTimeout
	}
	return StateError
}
