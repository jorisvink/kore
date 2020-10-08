if [ -z "$ROOT" ]; then
	echo "No ROOT set"
	exit 1
fi

SOURCES=sources
BUILD=$ROOT/build
FAKEROOT=$ROOT/fakeroot

LASTDIR=`pwd`

pushd() {
	LASTDIR=`pwd`
	cd $1
}

popd() {
	cd $LASTDIR
}

fetch() {
	url=$1
	name=$2

	if [ -f $SOURCES/$name.tar.gz ]; then
		return
	fi

	curl -L "$url" > $SOURCES/$name.tar.gz
}

default_build() {
	name=$1
	shift
	config=$*

	build $name ./configure --prefix=$FAKEROOT/$NAME $config
}

build() {
	name=$1
	shift
	configcmd=$*

	if [ -f $BUILD/$name/.built ]; then
		return
	fi

	rm -rf $BUILD/$name
	rm -rf $FAKEROOT/$name

	tar -zvxf $SOURCES/$name.tar.gz -C $BUILD

	pushd $BUILD/$name
	mkdir -p $FAKEROOT/$name

	$configcmd

	make -j
	make install
	popd

	touch $BUILD/$name/.built
}

setup() {
	mkdir -p $BUILD
	mkdir -p $SOURCES
	mkdir -p $FAKEROOT
}

setup
