// Package vt implements the VirusTotal API.
package vt

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"maps"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/VirusTotal/vt-go"
	"go.foxforensics.dev/checker/api"
)

// Key to use for VirusTotal
var Key string

// CheckIp returns if the IP is malicious.
func CheckIp(ip string) (*api.Result, error) {
	return request(vt.URL("ip_addresses/%s", ip))
}

// CheckDns returns if the domain is malicious.
func CheckDns(url string) (*api.Result, error) {
	return request(vt.URL("domains/%s", url))
}

// CheckUrl returns if the URL is malicious.
func CheckUrl(url string) (*api.Result, error) {
	return request(vt.URL("urls/%s", url))
}

// CheckFile returns if the file is malicious.
func CheckFile(file string) (*api.Result, error) {
	return request(vt.URL("files/%s", hashFile(file)))
}

func parseVerdict(obj *vt.Object, res *api.Result) {
	res.Stats.Bad = countStats(obj, []string{
		"malicious",
		"suspicious",
	})

	res.Stats.All = countStats(obj, []string{
		"malicious",
		"suspicious",
		"undetected",
		"harmless",
		"timeout",
		"confirmed-timeout",
		"failure",
		"type-unsupported",
	})

	res.Verdict, _ = obj.GetString("popular_threat_classification.suggested_threat_label")

	if len(res.Verdict) == 0 {
		switch {
		case res.Stats.Bad > 0:
			res.Verdict = api.Suspicious
		case res.Stats.All > 0:
			res.Verdict = api.Clean
		default:
			res.Verdict = api.Unrated
		}
	}
}

func parseDetails(obj *vt.Object, res *api.Result) {
	aly, err := obj.Get("last_analysis_results")

	if err != nil {
		return
	}

	m := aly.(map[string]any)

	for _, k := range slices.Sorted(maps.Keys(m)) {
		v := m[k].(map[string]any)

		if v["result"] == nil {
			continue
		}

		res.Details[v["engine_name"].(string)] = v["result"].(string)
	}
}

func countStats(obj *vt.Object, l []string) (n int) {
	for _, k := range l {
		v, _ := obj.GetInt64(fmt.Sprintf("last_analysis_stats.%s", k))
		n += int(v)
	}
	return
}

func hashFile(path string) string {
	f, err := os.Open(path)

	if err != nil {
		log.Fatalf("hashFile: %v", err)
	}

	defer func(f *os.File) {
		_ = f.Close()
	}(f)

	h := sha256.New()

	if _, err := io.Copy(h, f); err != nil {
		log.Fatalf("hashFile: %v", err)
	}

	return fmt.Sprintf("%x", h.Sum(nil))
}

func request(url *url.URL) (*api.Result, error) {
	res := &api.Result{Details: make(map[string]string)}

	vtc := vt.NewClient(Key, vt.WithHTTPClient(api.Client()))

	obj, err := vtc.GetObject(url)

	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			res.Verdict = api.Unknown
			return res, nil
		}

		return nil, err
	}

	parseDetails(obj, res)
	parseVerdict(obj, res)

	return res, nil
}
