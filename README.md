# check
Check different resources for malevolence.

```console
go install go.foxforensics.dev/check@latest
```

## Usage
```console
$ check <FILE|MAIL|URL|DNS|IP> value ...
```

## Environment
* `CHECK_VT_KEY` must be set to check `FILE`, `URL`, `DNS`, `IP`. 
* `CHECK_HIBP_KEY` must be set to check `MAIL`.

## License
Released under the [MIT License](LICENSE.md).