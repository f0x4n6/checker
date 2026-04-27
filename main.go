// Check different net resources.
//
// Usage:
//
//	check type value
//
// The arguments are:
//
//	type
//		    Hash algorithm to used (required).
//	value
//		    File or folder to hash (required).
package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"go.foxforensics.dev/check/api"
	"go.foxforensics.dev/check/api/hibp"
	"go.foxforensics.dev/check/api/vt"
)

func main() {
	if len(os.Args) < 3 || os.Args[1] == "--help" {
		_, _ = fmt.Fprintln(os.Stderr, "usage: check <file|mail|dns|url|ip> <path|text>")
		os.Exit(2)
	}

	key1 := os.Getenv("")
	key2 := os.Getenv("")

	var res *api.Result
	var err error

	switch strings.ToLower(os.Args[1]) {
	case "file":
		res, err = vt.CheckFileHash(os.Args[2], key1)
	case "mail":
		res, err = hibp.CheckMail(os.Args[2], key2)
	case "url":
		res, err = vt.CheckUrl(os.Args[2], key1)
	case "dns":
		res, err = vt.CheckDomain(os.Args[2], key1)
	case "ip":
		res, err = vt.CheckIp(os.Args[2], key1)
	default:
		log.Fatalf("type unknown: %s", os.Args[1])
	}

	if err != nil {
		log.Fatalf("api error: %v", err)
	}

	_, _ = fmt.Println(res.Verdict)
}
