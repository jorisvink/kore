Static Kore application that shows off a few things:

* Static build
* NOTLS flavor
* File uploads (/upload)
* Authentication blocks (/private)
* base64 encoding tests (/b64test)
* Parameter validator tests (/params-test)

Build:

```
    # kore build
```

Run:
```
	# ./static -n -r
```

The `-n` and `-r` flags are there in case there is no `chroot` and
`runas` configured, requiring start as root.
