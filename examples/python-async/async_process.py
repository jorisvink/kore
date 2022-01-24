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
# Asynchronous process example.
#
# Wait for the result of an external process asynchronously.
# The handler will execute "/bin/ls" on the current directory and
# read the result.
#

import kore
import json

@kore.route("/proc", methods=["get"])
async def async_proc(req):
    #
    # You may specify a timeout when creating the kore.proc object.
    # If the timeout is reached before the process exits kore will
    # raise a TimeoutError exception.
    #
    # Ex: set timeout to 100ms:
    #   proc = kore.proc("/bin/ls -lR", 100)

    proc = kore.proc("/bin/ls -lR")

    try:
        stdout = ""

        # Read until EOF (None is returned)
        while True:
            try:
                # Read from the process, with an optional 1 second timeout.
                # The recv() call will throw a TimeoutError exception if
                # the timeout has elapsed before any data was read.
                chunk = await proc.recv(1024, 1000)
                if chunk is None:
                    break
            except TimeoutError as e:
                print("recv() timed out: %s" % e)
                continue
            stdout += chunk.decode()

        # Reap the process.
        retcode = await proc.reap()

        # Respond with the return code + the result as JSON.
        payload = {
            "retcode": retcode,
            "stdout": stdout
        }

        data = json.dumps(payload, indent=4)
        req.response(200, data.encode())
    except Exception as e:
        # If an exception occurs we must kill the process first.
        proc.kill()
        errmsg = "Exception: %s" % e
        req.response(500, errmsg.encode())
