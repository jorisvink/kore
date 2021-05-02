#
# Copyright (c) 2018 Joris Vink <joris@coders.se>
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
# Simple socket example.
#
# The handler will asynchronously connect to the kore app itself and
# send an GET request to /socket-test and read the response.

import kore
import socket

@kore.route("/socket", methods=["get"])
async def async_socket(req):
    # Create the socket using Pythons built-in socket class.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Set it to nonblocking.
    sock.setblocking(False)

    # Create a kore.socket with kore.socket_wrap().
    conn = kore.socket_wrap(sock)

    # Asynchronously connect to 127.0.0.1 port 8888
    await conn.connect("127.0.0.1", 8888)
    kore.log(kore.LOG_INFO, "connected!")

    # Now send the GET request
    msg = "GET /socket-test HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
    await conn.send(msg.encode())
    kore.log(kore.LOG_INFO, "request sent!")

    # Read the response.
    data = await conn.recv(8192)
    kore.log(kore.LOG_INFO, "got response!")

    # Respond with the response from /socket-test.
    req.response(200, data)

    conn.close()

@kore.route("/socket-test", methods=["get"])
async def socket_test(req):
    # Delay response a bit, just cause we can.
    await kore.suspend(5000)
    req.response(200, b'response from /socket-test')
