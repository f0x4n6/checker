// Check different resources for malevolence.
//
// Usage:
//
//	check <FILE|MAIL|URL|DNS|IP> value ...
//
// The arguments are:
//
//	type
//		    Type of check (required).
//	value
//		    Value to check (required).
package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/fatih/color"
	"go.foxforensics.dev/check/api"
	"go.foxforensics.dev/check/api/hibp"
	"go.foxforensics.dev/check/api/vt"
)

func main() {
	if len(os.Args) < 3 || os.Args[1] == "--help" {
		_, _ = fmt.Fprintln(os.Stderr, "usage: check <FILE|MAIL|URL|DNS|IP> value ...")
		os.Exit(2)
	}

	hibp.Key = os.Getenv("CHECK_HIBP_KEY")
	vt.Key = os.Getenv("CHECK_VT_KEY")

	t := strings.ToLower(os.Args[1])

	if t == "mail" {
		if len(hibp.Key) == 0 {
			_, _ = fmt.Fprintf(os.Stderr, "[!] %s\n", color.RedString("CHECK_HIBP_KEY not set"))
			os.Exit(1)
		}
	} else {
		if len(vt.Key) == 0 {
			_, _ = fmt.Fprintf(os.Stderr, "[!] %s\n", color.RedString("CHECK_VT_KEY not set"))
			os.Exit(1)
		}
	}

	for _, v := range os.Args[2:] {
		var res *api.Result
		var err error

		switch t {
		case "mail":
			res, err = hibp.CheckMail(v)
		case "file":
			res, err = vt.CheckFile(v)
		case "url":
			res, err = vt.CheckUrl(v)
		case "dns":
			res, err = vt.CheckDns(v)
		case "ip":
			res, err = vt.CheckIp(v)
		default:
			log.Fatalf("unknown type: %s", os.Args[1])
		}

		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[!] %s\n", color.RedString(err.Error()))
			continue
		}

		switch res.Verdict {
		case api.Suspicious, api.Breached:
			_, _ = fmt.Printf("[!] %s\n", color.RedString(v))
		case api.Unrated, api.Unknown:
			_, _ = fmt.Printf("[?] %s\n", color.YellowString(v))
		case api.Clean:
			_, _ = fmt.Printf("[*] %s\n", color.GreenString(v))
		default:
			_, _ = fmt.Printf("[!] %s  %s\n", color.RedString(v), color.New(color.BgRed, color.Bold).Sprintf(" %s ", res.Verdict))
		}
	}
}
