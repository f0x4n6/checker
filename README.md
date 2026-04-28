# checker
Check different resources for malevolence.

```console
go install go.foxforensics.dev/checker@latest
```

## Usage
```console
$ checker <FILE|MAIL|URL|DNS|IP> value ...
```

## APIs

### VirusTotal
> The environment variable `CHECKER_VT_KEY` must be set.

* Check if an IP / URL / domain name has been used in malicious activities
* Check if a file is malicious by its hash

### HaveIBeenPwned
> The environment variable `CHECKER_HIBP_KEY` must be set.

* Check if an mail address has been breached

## License
Released under the [MIT License](LICENSE.md).
