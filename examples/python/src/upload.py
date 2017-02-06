#
# Copyright (c) 2017 Joris Vink <joris@coders.se>
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

# Processing incoming files in a multipart form.

import kore

#
# This handler receives a POST with a multipart data.
# It extracts the file called "file" and writes it to a new file.
#
def upload(req):
	# We only allow POST's.
	if req.method is not kore.METHOD_POST:
		req.response_header("allow", "post")
		req.response(400, b'')
		return

	# Ask kore to parse incoming multipart data.
	req.populate_multi()

	# Lookup the file called "file".
	file = req.file_lookup("file")
	if not file:
		req.response(400, b'')
		return

	kore.log(kore.LOG_INFO,
	    "%s (%s, filename=%s)" % (file, file.name, file.filename))

	# Open target file.
	f = open(file.filename, "wb")
	if not f:
		req.response(500, b'')
		return

	# Read all data from incoming file and write it to the output file.
	len = True
	while len:
		len, bytes = file.read(1024)
		kore.log(kore.LOG_INFO, "got %d bytes of data" % len)
		f.write(bytes)

	f.close()
	req.response(200, b'')
