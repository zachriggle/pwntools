# Testing in a Can

This is a Dockerfile which has all of the requirements for testing pwntools.

It's pretty simple, just run `make`.  All of your changes will be copied into the docker container, and the doctest suite will be executed automatically.

```shell
$ make -C travis/docker ANDROID=yes
```

## Options

Currently, the only option is `ANDROID`, which controls whether or not to run the Android test.  The valid options are ``yes`` (the default) and ``no``.

## Known Issues

Currently, some tests are broken when executed in Docker.

- `process.leak()` is broken, as it relies on `/proc/<pid>/mem`
- `srop` tests are broken, since there are issues with `SYS_sigreturn` when running in Docker.
