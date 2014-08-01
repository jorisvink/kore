[![Coverity Status](https://scan.coverity.com/projects/1844/badge.svg)](https://scan.coverity.com/projects/1844)
About
-----
Kore (https://kore.io) is an ultra fast web server / framework for web
applications developed in C. It provides a set of API functions you can
use to build a dynamic library which is loaded into Kore directly.

Kore is an ideal candidate for developing robust, fast and safe web applications.

Features
--------
* Supports SNI
* Supports SPDY/3
* Supports HTTP/1.1
* Lightweight background tasks
* Built-in parameter validation
* Only HTTPS connections allowed
* Multiple modules can be loaded at once
* Built-in asynchronous PostgreSQL support
* Load your web application as a precompiled C library
* Event driven architecture with per CPU core worker processes
* Modules can be reloaded on-the-fly, even while serving content

License
-------
* Kore is licensed under the ISC license

Platforms supported
-------------------
* Linux
* OpenBSD
* FreeBSD
* OSX

See https://kore.io/doc/#section1.1 for more information.

Releases
--------
* [2014-08-25] Version 1.2 will be released
* [2014-03-01] Version 1.1 - https://kore.io/release/kore-1.1-stable.tgz

Building Kore
-------------

Requirements
* libz
* openssl >= 1.0.1g

Requirements for background tasks
* pthreads

Requirements for pgsql
* libpq

Normal compilation and installation:

```
# git clone https://github.com/jorisvink/kore.git
# cd kore
# make
# make install
```

If you would like to build a specific flavor, you can enable
those by setting a shell environment variable before running **_make_**.

* TASKS=1 (compiles in task support)
* PGSQL=1 (compiles in pgsql support)
* DEBUG=1 (enables use of -d for debug)
* BENCHMARK=1 (compiles Kore without OpenSSL)
* KORE_PEDANTIC_MALLOC=1 (zero all allocated memory)

Example libraries
-----------------

You can find example libraries under **_contrib/examples/_**.

The examples should be compiled using the supplied **build.sh** scripts
and assume you have installed the header files using make install.

I apologize for unclear examples or documentation, I am working on
improving those.

Bugs, contributions and more
----------------------------

If you run into any bugs, have suggestions or patches please
contact me at joris@coders.se.

More information can be found on https://kore.io/
