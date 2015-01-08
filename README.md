# rlogd
Reliable LOG Daemon

## Build
***Clone the code***

    $ git clone git://github.com/pandax381/rlogd.git

***Build program***

    $ cd rlogd
    $ ./autogen.sh
    $ ./configure
    $ make
    $ sudo make install

Note: This program requires libev.

Note: This program has been tested with Linux (kernel 3.2.0) and Mac OSX (10.9.5)

## Config file
    # rlogd.conf.example
    <source>
        type forward
        bind unix:///var/run/rlogd/rlogd.sock
    </source>

    <source>
        type forward
        bind 0.0.0.0:10381
        label forwarded
    </source>

    <match ^example\.>
        type forward
        target 127.0.0.1:10381
        buffer_path /var/run/rlogd/buf/
    </match>

    <label ^forwarded$>
        <match ^example\.acc\.>
            type file
            path /var/run/rlogd/logs/example/%Y-%m-%d/acc_%H%M.log
        </match>
        <match ^example\.err\.>
            type file
            path /var/run/rlogd/logs/example/%Y-%m-%d/err_%H%M.log
        </match>
        <match ^example\.app\.>
            type file
            path /var/run/rlogd/logs/example/%Y-%m-%d/app_%H%M.log
        </match>
    </label>
