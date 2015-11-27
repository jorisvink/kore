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
* Lightweight background tasks
* Built-in parameter validation
* Only HTTPS connections allowed
* Multiple modules can be loaded at once
* Built-in asynchronous PostgreSQL support
* Default sane TLS ciphersuites (PFS in all major browsers)
* Load your web application as a precompiled dynamic library
* Modules can be reloaded on-the-fly, even while serving content
* Event driven (epoll/kqueue) architecture with per CPU core workers

License
-------
* Kore is licensed under the ISC license

Platforms supported
-------------------
* Linux
* OpenBSD
* FreeBSD
* OSX

See https://kore.io/doc/#requirements for more information.

Latest release
--------------
* [2015-05-21] version 1.2.3 - https://kore.io/release/kore-1.2.3-release.tgz

Old releases
------------
* [2015-04-09] version 1.2.2 - https://kore.io/release/kore-1.2.2-release.tgz
* [2014-12-12] version 1.2.1 - https://kore.io/release/kore-1.2.1-release.tgz
* [2014-08-25] version 1.2 - https://kore.io/release/kore-1.2-stable.tgz
* [2014-03-01] version 1.1 - https://kore.io/release/kore-1.1-stable.tgz

Building Kore
-------------

Requirements
* openssl (latest is always the safest bet, right?)
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

Example libraries
-----------------

You can find example libraries under **_examples/_**.

The examples contain a README file with instructions on how
to build or use them.

I apologize for unclear examples or documentation, I am working on
improving those.

Bugs, contributions and more
----------------------------

If you run into any bugs, have suggestions or patches please
contact me at joris@coders.se.

More information can be found on https://kore.io/
