// Package hibp implements the HaveIBeenPwned API.
package hibp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"go.foxforensics.dev/checker/api"
)

const v3 = "https://haveibeenpwned.com/api/v3"

// Key to use for HaveIBeenPwned
var Key string

type breach struct {
	Title        string `json:"Title,omitempty"`
	BreachDate   string `json:"BreachDate,omitempty"`
	IsVerified   bool   `json:"IsVerified,omitempty"`
	IsFabricated bool   `json:"IsFabricated,omitempty"`
}

// CheckMail returns if the mail adresse has been compromised.
func CheckMail(mail string) (*api.Result, error) {
	return request(fmt.Sprintf("%s/breachedaccount/%s?truncateResponse=false", v3, url.QueryEscape(mail)))
}

func parseVerdict(br []breach, res *api.Result) {
	for _, v := range br {
		res.Stats.All += 1

		if v.IsVerified && !v.IsFabricated {
			res.Stats.Bad += 1
		}
	}

	if res.Stats.Bad > 0 {
		res.Verdict = api.Breached
	} else {
		res.Verdict = api.Clean
	}
}

func parseDetails(br []breach, res *api.Result) {
	for _, v := range br {
		res.Details[v.Title] = v.BreachDate
	}
}

func getBreaches(r *http.Response) ([]breach, error) {
	var br []breach

	b, err := io.ReadAll(r.Body)

	_ = r.Body.Close()

	if err != nil {
		return nil, err
	}

	return br, json.Unmarshal(b, &br)
}

func request(url string) (*api.Result, error) {
	res := &api.Result{Details: make(map[string]string)}

	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		return nil, err
	}

	req.Header.Add("user-agent", api.UserAgent)
	req.Header.Add("hibp-api-key", Key)

	resp, err := api.Client().Do(req)

	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(http.StatusText(resp.StatusCode))
	}

	br, err := getBreaches(resp)

	if err != nil {
		return nil, err
	}

	parseDetails(br, res)
	parseVerdict(br, res)

	return res, nil
}
