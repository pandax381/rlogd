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

## Usage

### rlogd

    usage: rlogd [options]
      options:
        -c, --conf=PATH  # configuration file (default: /etc/rlogd.conf)
        -d, --debug      # enable debug mode
        -F, --foreground # foreground (not a daemon)
        -p, --pid=PATH   # PID file (default: /var/run/rlogd.pid)
        -h, --help       # print this message
        -v, --version    # show version

### rloggerd

    usage: rloggerd [options]
      options:
        -d, --debug         # debug mode
        -l, --listen=ADDR   # listen address (default: unix:///var/run/rlogd/rloggerd.sock)
        -t, --target=TARGET # target address (default: unix:///var/run/rlogd/rlogd.sock)
        -u, --user=USER     # socket file owner
        -m, --mode=MODE     # socket file permission (default: 666)
        -b, --buffer=PATH   # file buffer directory path (default: /var/run/rlogd/rloggerd.buf)
        -c, --chunk=SIZE    # maximum length of the chunk (default: 8388608)
        -f, --flush=TIME    # time to flush the chunk (default: 5)
            --help          # show this message
            --version       # show version

### rlogger

    usage: rlogger [options] <tag>
      options:
        -d, --debug         # debug mode
        -t, --target=TARGET # target (default: unix:///var/run/rlogd/rloggerd.sock)
        -T, --timeout=SEC   # connection timeout sec (default: system default)
        -c, --chunk=SIZE    # maximum length of the chunk (default: 8388608)
        -f, --flush=TIME    # time to flush the chunk (default: 5)
            --help          # show this message
            --version       # show version

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

    <match example.**>
        type forward
        target 127.0.0.1:10381
        buffer_path /var/run/rlogd/buf/
    </match>

    <label forwarded>
        <match example.acc.**>
            type file
            path /var/run/rlogd/logs/example/%Y-%m-%d/acc_%H%M.log
        </match>
        <match example.err.**>
            type file
            path /var/run/rlogd/logs/example/%Y-%m-%d/err_%H%M.log
        </match>
        <match example.app.**>
            type file
            path /var/run/rlogd/logs/example/%Y-%m-%d/app_%H%M.log
        </match>
    </label>
