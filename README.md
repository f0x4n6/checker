# checker
Check different resources for malevolence.

```console
go install go.foxforensics.dev/checker@latest
```

## Usage
```console
$ checker <FILE|MAIL|URL|DNS|IP> value ...
```

## Services
VirusTotal:
> IP, DNS, URL, File (SHA256)

HaveIBeenPwned:
> Mail Address Breaches

## Environment
The environment variables `CHECKER_VT_KEY` and `CHECKER_HIBP_KEY` must be set with a user specific API keys.

## License
Released under the [MIT License](LICENSE.md).
