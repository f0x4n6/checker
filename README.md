# checker
Check different resources for malevolence.

```console
go install go.foxforensics.dev/checker@latest
```

## Usage
```console
$ checker <FILE|MAIL|URL|DNS|IP> value ...
```

## Environment
* `CHECKER_VT_KEY` must be set to check `FILE`, `URL`, `DNS`, `IP`. 
* `CHECKER_HIBP_KEY` must be set to check `MAIL`.

## License
Released under the [MIT License](LICENSE.md).