About
-----
[![Build Status](https://travis-ci.org/jorisvink/kore.svg?branch=master)](https://travis-ci.org/jorisvink/kore)

Kore (https://kore.io) is an easy to use web application platform for
writing scalable web APIs in C. Its main goals are security, scalability
and allowing rapid development and deployment of such APIs.

Because of this Kore is an ideal candidate for building robust, scalable and secure web things.

Key Features
------------
* Supports SNI
* Supports HTTP/1.1
* Websocket support
* Privseps by default
* TLS enabled by default
* Optional background tasks
* Built-in parameter validation
* Optional asynchronous PostgreSQL support
* Optional support for page handlers in Python
* Private keys isolated in separate process (RSA and ECDSA)
* Default sane TLS ciphersuites (PFS in all major browsers)
* Modules can be reloaded on-the-fly, even while serving content
* Event driven (epoll/kqueue) architecture with per CPU worker processes
* Build your web application as a precompiled dynamic library or single binary

And loads more.

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
* MacOS

Building Kore
-------------
Clone this repository. I highly recommend using master until the 3.0.0 release
is tagged as the 2.x releases are outdated. The master branch is always stable.

Requirements
* openssl (1.0.2k+ or 1.1.0e+)
  (note: this requirement drops away when building with NOTLS=1 NOHTTP=1)
  (note: libressl should work as a replacement)

Requirements for background tasks (optional)
* pthreads

Requirements for pgsql (optional)
* libpq

Requirements for python (optional)
* Python 3.6+

Normal compilation and installation:

```
$ cd kore
$ make
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
* PYTHON=1 (compiles in the Python support)

Note that certain build flavors cannot be mixed together and you will just
be met with compilation errors.

Example applications
-----------------
You can find example applications under **_examples/_**.

The examples contain a README file with instructions on how
to build or use them.

Bugs, contributions and more
----------------------------
If you run into any bugs, have suggestions or patches please
contact me at joris@coders.se.

More information can be found on https://kore.io/
