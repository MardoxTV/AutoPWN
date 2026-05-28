package portscan

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/autopwn/scanner/pkg/models"
)

// Scan performs a concurrent TCP port scan and returns open ports.
func Scan(req models.ScanRequest) (result models.ScanResult) {
	// Top-level panic guard — scanner service must never crash
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[portscan] recovered from panic: %v", r)
			result.Error = fmt.Sprintf("scanner panic: %v", r)
		}
	}()

	if req.Target == "" {
		return models.ScanResult{Error: "target is required"}
	}

	start := time.Now()
	ports := parsePorts(req.Ports)
	if len(ports) == 0 {
		return models.ScanResult{Target: req.Target, Error: "no valid ports in spec: " + req.Ports}
	}

	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	rate := req.Rate
	if rate <= 0 {
		rate = 1000
	}
	// Cap rate to prevent resource exhaustion
	if rate > 10000 {
		rate = 10000
	}

	sem := make(chan struct{}, rate)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var openPorts []models.OpenPort

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			// Per-goroutine panic recovery — one bad port must not kill the scan
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[portscan] goroutine panic on port %d: %v", p, r)
				}
			}()

			proto := req.Protocol
			if proto == "" {
				proto = "tcp"
			}
			address := fmt.Sprintf("%s:%d", req.Target, p)
			conn, err := net.DialTimeout(proto, address, timeout)
			if err != nil {
				return
			}
			banner := grabBanner(conn, timeout)
			conn.Close()

			mu.Lock()
			openPorts = append(openPorts, models.OpenPort{
				Port:     p,
				Protocol: proto,
				Banner:   banner,
			})
			mu.Unlock()
		}(port)
	}

	wg.Wait()

	return models.ScanResult{
		Target:         req.Target,
		OpenPorts:      openPorts,
		ScanDurationMs: time.Since(start).Milliseconds(),
	}
}

func grabBanner(conn net.Conn, timeout time.Duration) string {
	conn.SetReadDeadline(time.Now().Add(timeout / 2))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n > 0 {
		return strings.TrimSpace(string(buf[:n]))
	}
	return ""
}

func parsePorts(spec string) []int {
	var ports []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			if len(bounds) != 2 {
				continue
			}
			lo, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 != nil || err2 != nil {
				continue
			}
			for p := lo; p <= hi; p++ {
				ports = append(ports, p)
			}
		} else {
			p, err := strconv.Atoi(part)
			if err == nil {
				ports = append(ports, p)
			}
		}
	}
	return ports
}

// ReadLine is used for banner grabbing line-by-line
func readLine(conn net.Conn, timeout time.Duration) string {
	conn.SetReadDeadline(time.Now().Add(timeout))
	scanner := bufio.NewScanner(conn)
	if scanner.Scan() {
		return scanner.Text()
	}
	return ""
}
