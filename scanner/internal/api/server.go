package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/autopwn/scanner/internal/bruteforce"
	"github.com/autopwn/scanner/internal/portscan"
	"github.com/autopwn/scanner/pkg/models"
)

func NewServer(port string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/scan", recoverMiddleware(handleScan))
	mux.HandleFunc("/brute", recoverMiddleware(handleBrute))
	return mux
}

// recoverMiddleware catches panics in handlers and returns a 500 instead of
// crashing the scanner process.
func recoverMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[api] recovered panic in %s: %v", r.URL.Path, rec)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next(w, r)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req models.ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Target == "" || req.Ports == "" {
		http.Error(w, "target and ports are required", http.StatusBadRequest)
		return
	}

	log.Printf("[scan] %s ports=%s proto=%s", req.Target, req.Ports, req.Protocol)
	result := portscan.Scan(req)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleBrute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req models.BruteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Target == "" || req.Service == "" {
		http.Error(w, "target and service are required", http.StatusBadRequest)
		return
	}

	log.Printf("[brute] %s:%d service=%s combos=%d",
		req.Target, req.Port, req.Service, len(req.Userlist)*len(req.Passlist))
	result := bruteforce.Brute(req)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
