Kore release procedure:

$next = next release
$prev = previous release

kore:
    $ git checkout 4.x-releng
    $ git merge master
        [update RELEASE, README.md]
    $ git commit -a -m "update for $next"
    $ git tag -a $next -m "Kore $next"
    $ git archive --format=tgz --prefix=kore-$next/ -o ~/kore-$next.tgz $next
    $ minisign -S -c "Kore $next release"  -m kore-$next.tar.gz
    $ shasum -a256 kore-$next.tar.gz > kore-$next.tar.gz.sha256
    $ git push --tags origin 4.x-releng
    $ git push --tags github 4.x-releng

kore-site:
    $ cp ~/kore-$next* webroot/releases
    $ cp webroot/releases/$prev.html webroot/releases/$next.html
        [update all relevant links]
        [write changelog on release page]
    $ git add webroot && git commit -a -m "update to $next"
    $ git push origin master

    [on nightfall]
    $ cd kore-site && git pull origin master && make install-docs

kore-docker:
    $ cp -R $prev $next
    $ ./build.sh $next
