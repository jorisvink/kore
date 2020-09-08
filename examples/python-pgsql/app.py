#
# Copyright (c) 2017-2018 Joris Vink <joris@coders.se>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

# Asynchronous postgresql queries with Python.

import json
import kore

class KoreApp:
    def configure(self, args):
        # Register the path to our database when Kore starts.
        kore.dbsetup("db", "host=/tmp dbname=test")

    # A handler that returns 200 OK with hello as body.
    def hello(self, req):
        req.response(200, b'hello\n')

    #
    # The query handler that fires of the query and returns a coroutine.
    #
    # Kore will resume this handler when the query returns a result or
    # is successful.
    #
    # The kore.pgsql() method can throw exceptions, most notably a
    # GeneratorExit in case the client connection went away before
    # the query was able to be completed.
    #
    # In this example we're not doing any exception handling.
    #
    async def query(self, req):
        result = await kore.dbquery("db", "SELECT * FROM coders")
        req.response(200, json.dumps(result).encode("utf-8"))

    #
    # A slow query that returns after 10 seconds.
    #
    async def slow(self, req):
        result = await kore.dbquery("db", "SELECT * FROM pg_sleep(10)")
        req.response(200, json.dumps(result).encode("utf-8"))

# Set the application Kore will run to our class.
koreapp = KoreApp()
