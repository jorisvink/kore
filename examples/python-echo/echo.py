#
# Copyright (c) 2013-2018 Joris Vink <joris@coders.se>
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

import kore
import socket

class EchoServer:
    # Setup socket + wrap it inside of a kore socket so we can use it.
    def __init__(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 6969))
        sock.listen()

        self.conn = kore.socket_wrap(sock)

    # Wait for a new client to connect, then create a new task
    # that calls handle_client with the ocnnected client as
    # the argument.
    async def run(self):
        while True:
            try:
                client = await self.conn.accept()
                kore.task_create(self.handle_client(client))
                client = None
            except Exception as e:
                kore.fatal("exception %s" % e)

    # Each client will run as this co-routine.
    # In this case we pass a timeout of 1 second to the recv() call
    # which will throw a TimeoutError exception in case the timeout
    # is hit before data is read from the socket.
    #
    # This timeout argument is optional. If none is specified the call
    # will wait until data becomes available.
    async def handle_client(self, client):
        while True:
            try:
                data = await client.recv(1024, 1000)
                if data is None:
                    break
                await client.send(data)
            except TimeoutError as e:
                print("timed out reading (%s)" % e)
            except Exception as e:
                print("client got exception %s" % e)
        client.close()

# Setup the server object.
server = EchoServer()

# Create a task that will execute inside of Kore as a co-routine.
kore.task_create(server.run())
