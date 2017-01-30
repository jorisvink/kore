# using kore websockets via python.

import kore

def onconnect(c):
	kore.log(kore.LOG_INFO, "%s: py connected" % c)

def onmessage(c, op, data):
	kore.websocket_broadcast(c, op, data, kore.WEBSOCKET_BROADCAST_GLOBAL)

def ondisconnect(c):
	kore.log(kore.LOG_INFO, "%s: py disconnecting" % c)

def ws_connect(req):
	try:
		req.websocket_handshake("onconnect", "onmessage", "ondisconnect")
	except:
		req.response(500, b'')

	return kore.RESULT_OK
