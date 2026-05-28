package models

// ScanRequest is the payload for POST /scan
type ScanRequest struct {
	Target    string `json:"target"`
	Ports     string `json:"ports"`      // e.g. "1-65535" or "80,443,8080"
	Protocol  string `json:"protocol"`   // tcp | udp
	Rate      int    `json:"rate"`       // max concurrent connections
	TimeoutMs int    `json:"timeout_ms"` // per-connection timeout
}

// OpenPort represents a single open port result
type OpenPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Banner   string `json:"banner,omitempty"`
}

// ScanResult is the response for POST /scan
type ScanResult struct {
	Target         string     `json:"target"`
	OpenPorts      []OpenPort `json:"open_ports"`
	ScanDurationMs int64      `json:"scan_duration_ms"`
	Error          string     `json:"error,omitempty"`
}

// BruteRequest is the payload for POST /brute
type BruteRequest struct {
	Target    string   `json:"target"`
	Port      int      `json:"port"`
	Service   string   `json:"service"` // ssh | ftp | http
	Userlist  []string `json:"userlist"`
	Passlist  []string `json:"passlist"`
	Threads   int      `json:"threads"`
	TimeoutMs int      `json:"timeout_ms"`
}

// Credential holds a discovered username/password pair
type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// BruteResult is the response for POST /brute
type BruteResult struct {
	Found      bool        `json:"found"`
	Credential *Credential `json:"credential,omitempty"`
	Attempts   int         `json:"attempts"`
	DurationMs int64       `json:"duration_ms"`
	Error      string      `json:"error,omitempty"`
}
