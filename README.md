
Introduction
============

*evhttp* is my personal implementation of the HTTP backend for [libev](http://software.schmorp.de/pkg/libev.html).   Currently, it is still under development.

- Basic GET method is supported for the callback.

Performance
===========

Testing Machine:

    $ uname -a
    Linux MyMachine 3.12.13-gentoo #3 SMP
    Tue Apr 8 09:26:19 KST 2014
    x86_64 Intel(R) Core(TM) i7-3770K CPU @ 3.50GHz GenuineIntel GNU/Linux

Since *evhttp* is not finished yet, measuring the performance does not make sense.  Still, it may be worthwhile to get the tentative TPS for the upper bound.  Here are some best TPS that I got using [weighttp](http://redmine.lighttpd.net/projects/weighttp/wiki) with following options:

    $ # without keepalive, 8 threads, 100 concurrency
    $ weighttp -c 100 -t 8 -n 10000 http://localhost:8082/
    $ # with keepalive, 8 threads, 100 concurrency
    $ weighttp -k -c 100 -t 8 -n 10000 http://localhost:8082/

Current best results are:

 - 1 process, 1 thread, no keepalive: 23744 req/s
 - 1 process, 1 thread, keepalive: 72625 req/s
 - 1 process, 4 threads, no keepalive: 57861 req/s
 - 1 process, 4 threads, keepalive: 170059 req/s
 - 4 processes (each has 1 thread), no keepalive: 54381 req/s
 - 4 processes (each has 1 thread), keepalive: 199820 req/s


License
=======

*evhttp* is distributed under the [GNU Lessor General Public License 2.1](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html).

*evhttp* has following dependencies:

- [uthash](http://troydhanson.github.io/uthash/), uses [BSD-like license](http://troydhanson.github.io/uthash/license.html) here.

*evhttp* uses _xobstack_, which is mildly modified version of the GNU obtack, which can be obtained from various GNU project such as glibc, GCC, libibery, gnulib.

