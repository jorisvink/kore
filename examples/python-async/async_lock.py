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
# Locking example.
#
# The handler for /lock will grab the shared lock, suspend itself for
# 5 seconds before releasing the lock and responding.
#
# While the lock is held, other requests to /lock will block until it
# is released.

import kore

# The shared lock
lock = kore.lock()

@kore.route("/lock", methods=["get"])
async def async_lock(req):
    # A kore.lock should be used with the "async with" syntax.
    async with lock:
        # Suspend for 5 seconds.
        await kore.suspend(5000)

        # Now respond.
        req.response(200, b'')
