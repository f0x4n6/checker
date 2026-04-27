package api

import (
	"encoding/json"
	"net/http"
	"time"
)

const (
	Clean      = "clean"
	Unknown    = "unknown"
	Unrated    = "unrated"
	Breached   = "breached"
	Suspicious = "suspicious"
)

var (
	Idle      = 0
	Timeout   = time.Second * 30
	UserAgent = "fox forensics check"
)

type Result struct {
	Verdict string            `json:"verdict,omitempty"`
	Details map[string]string `json:"details,omitempty"`
	Stats   struct {
		All int `json:"all,omitempty"`
		Bad int `json:"bad,omitempty"`
	} `json:"stats,omitempty"`
}

func (res *Result) ToJSON() string {
	b, _ := json.MarshalIndent(res, "", "  ")
	return string(b)
}

func (res *Result) ToJSONL() string {
	b, _ := json.Marshal(res)
	return string(b)
}

// Client HTTP client
func Client() *http.Client {
	return &http.Client{
		Timeout: Timeout,
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			IdleConnTimeout:     Timeout,
			TLSHandshakeTimeout: Timeout,
			MaxIdleConnsPerHost: Idle,
		},
	}
}
