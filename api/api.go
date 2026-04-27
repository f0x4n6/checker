// Package api provides a general API result.
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

// Timeout to use (general)
var Timeout = time.Second * 30

// UserAgent to use (general)
var UserAgent = "checker"

// Result of API call.
type Result struct {
	Verdict string            `json:"verdict,omitempty"`
	Details map[string]string `json:"details,omitempty"`
	Stats   struct {
		All int `json:"all,omitempty"`
		Bad int `json:"bad,omitempty"`
	} `json:"stats,omitempty"`
}

// ToJSON returns the result as JSON object.
func (res *Result) ToJSON() string {
	b, _ := json.MarshalIndent(res, "", "  ")
	return string(b)
}

// ToJSONL returns the result as JSON lines.
func (res *Result) ToJSONL() string {
	b, _ := json.Marshal(res)
	return string(b)
}

// Client returns the default HTTP client.
func Client() *http.Client {
	return &http.Client{
		Timeout: Timeout,
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			IdleConnTimeout:     Timeout,
			TLSHandshakeTimeout: Timeout,
			MaxIdleConnsPerHost: 0,
		},
	}
}
