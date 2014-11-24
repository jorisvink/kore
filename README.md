About
-----
Kore (https://kore.io) is an easy to use web application framework for
writing scalable web APIs in C. Its main goals are security, scalability
and allowing rapid development and deployment of such APIs.

Because of this Kore is an ideal candidate for building robust, scalable and secure web things.

Features
--------
* Supports SNI
* Supports SPDY/3.1
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

Releases
--------
* [2014-08-25] Version 1.2 - https://kore.io/release/kore-1.2-stable.tgz
* [2014-03-01] Version 1.1 - https://kore.io/release/kore-1.1-stable.tgz

Building Kore
-------------

Requirements
* libz
* openssl >= 1.0.1i

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
