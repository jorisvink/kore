A simple HTML5 video streaming service using Kore.

Building:
```
	You must first place a test video inside the videos/ folder. I tested
	this using Big Buck Bunny (ogg version) on Chrome. But any video that
	can be played with HTML5 works.

	If you did not save your video as videos/video.ogg make sure you
	update the assets/video.html file to point to the right video.

	When done, run a kodev build.
```

Run:
```
	kodev run
```

Visit the URI and you should see a video stream.

Frontend parts from video.js: http://www.videojs.com/
