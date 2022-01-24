#
# Copyright (c) 2019 Joris Vink <joris@coders.se>
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

#
# Asynchronous HTTP client example.
#

import kore

# Handler called for /httpclient
@kore.route("/httpclient", methods=["get"])
async def httpclient(req):
    # Create an httpclient.
    client = kore.httpclient("https://kore.io")

    # Do a simple GET request.
    print("firing off request")
    status, body = await client.get()
    print("status: %d, body: '%s'" % (status, body))

    # Reuse and perform another GET request, returning headers too this time.
    status, headers, body = await client.get(return_headers=True)
    print("status: %d, headers: '%s'" % (status, headers))

    # What happens if we post something?
    status, body = await client.post(body=b"hello world")
    print("status: %d, body: '%s'" % (status, body))

    # Add some custom headers to our requests.
    status, body = await client.get(
        headers={
            "x-my-header": "async-http"
        }
    )

    req.response(200, b'async done')
