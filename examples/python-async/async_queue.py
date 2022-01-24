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
# Asynchronous queue example.
#

import kore

# The shared queue.
tq = kore.queue()

# Entry point for our independent coroutine that is created when kore starts.
async def queue_helper():
    while True:
        # Wait for a dictionary to arrive.
        obj = await tq.pop()
        kore.log(kore.LOG_INFO, "coro(): received %s" % obj)

        # Create a message to send back.
        msg = "%d = %s" % (kore.time(), obj["msg"])

        # Send it on the received queue.
        obj["rq"].push(msg)

@kore.route("/queue", methods=["get"])
async def async_queue(req):
    # Create our own queue.
    rq = kore.queue()

    # The dictionary we are going to send.
    obj = {
        # Receive queue object.
        "rq": rq,
        "msg": "hello"
    }

    # Push it onto the tq queue now, which will wake up the other coroutine.
    tq.push(obj)

    # Wait for a response.
    response = await rq.pop()

    # Send the response to the client.
    req.response(200, response.encode())
