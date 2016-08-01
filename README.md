About
-----
[![Build Status](https://travis-ci.org/jorisvink/kore.svg?branch=master)](https://travis-ci.org/jorisvink/kore)

Kore (https://kore.io) is an easy to use web application framework for
writing scalable web APIs in C. Its main goals are security, scalability
and allowing rapid development and deployment of such APIs.

Because of this Kore is an ideal candidate for building robust, scalable and secure web things.

Features
--------
* Supports SNI
* Supports HTTP/1.1
* Websocket support
* Privseps by default
* Lightweight background tasks
* Built-in parameter validation
* Only HTTPS connections allowed
* Built-in asynchronous PostgreSQL support
* Private keys isolated in separate process (RSA and ECDSA)
* Default sane TLS ciphersuites (PFS in all major browsers)
* Modules can be reloaded on-the-fly, even while serving content
* Event driven (epoll/kqueue) architecture with per CPU core workers
* Build your web application as a precompiled dynamic library or single binary

License
-------
* Kore is licensed under the ISC license

Documentation
--------------
[Read the documentation](https://jorisvink.gitbooks.io/kore-doc/content/)

Platforms supported
-------------------
* Linux
* OpenBSD
* FreeBSD
* OSX

Building Kore
-------------
Grab the [latest release](https://github.com/jorisvink/kore/releases/tag/2.0.0-release)  tarball or clone the repository.

Requirements
* openssl (latest)
  (note: this requirement drops away when building with NOTLS=1 NOHTTP=1)

Requirements for background tasks (optional)
* pthreads

Requirements for pgsql (optional)
* libpq

Normal compilation and installation:

```
# cd kore
# make
# make install
```

If you would like to build a specific flavor, you can enable
those by setting a shell environment variable before running **_make_**.

* TASKS=1 (compiles in task support)
* PGSQL=1 (compiles in pgsql support)
* DEBUG=1 (enables use of -d for debug)
* NOTLS=1 (compiles Kore without TLS)
* NOHTTP=1 (compiles Kore without HTTP support)
* NOOPT=1 (disable compiler optimizations)
* JSONRPC=1 (compiles in JSONRPC support)

Example applications
-----------------
You can find example applications under **_examples/_**.

The examples contain a README file with instructions on how
to build or use them.

Bugs, contributions and more
----------------------------
If you run into any bugs, have suggestions or patches please
contact me at joris@coders.se.

If you feel like hanging out or just chatting there is an [IRC chatroom (#kore-dev@irc.freenode.org)](https://webchat.freenode.net?channels=kore-dev).

More information can be found on https://kore.io/
