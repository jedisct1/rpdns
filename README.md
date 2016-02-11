![RPDNS](https://raw.github.com/jedisct1/rpdns/master/rpdns.png)

RPDNS is a caching reverse DNS proxy.

```
[Clients] -> [RPDNS] -> [authoritative servers]
```

RPDNS accepts DNS queries, and responds from its own cache or after
forwarding them to a set of authoritative servers.

Although queries can be forwarded to recursive servers as well, RPDNS
itself does not perform any recursion. Its main purpose is to reduce
the load on authoritative servers, and to mitigate denial-of-service
attacks.

Features
--------

* EDNS0 support. Forwarded queries are rewritten in order to accept
large payloads over UDP, independently from the payload size
advertised by the client.
* Response rate limiting in order to protect upstream servers against
resource exhaustion.
* Validation - Do not forward invalid queries and queries that are not
fully qualified to upstream servers.
* `ANY` queries are answered directly as a synthesized `HINFO` record.
* TCP and UDP support; support for truncated responses.
* ARC-based cache for DNS responses.
* DNSSEC support.
* Basic failover/load balancing with consistent hashing.
* Resilience against outages of upstream servers.

Install
-------

```bash
$ go get github.com/jedisct1/rpdns
```

Usage
-----

Sample usage:
```bash
# rpdns -upstream 114.114.114.114:53,114.114.115.115:53 -maxclients 100 -maxfailures 2
```

Make sure to raise the number of allowed number of file descriptors to at least
`maxclients * 2`.

Available command-line options:
```
Usage of ./rpdns:
  -cachesize int
        Number of cached responses (default 1048576)
  -debug
        Debug mode
  -listen string
        Address to listen to (TCP and UDP) (default ":53")
  -local-rrs string
        Config files with local records
  -maxclients uint
        Maximum number of simultaneous clients (default 1000)
  -maxfailures uint
        Number of unanswered queries before a server is temporarily considered offline (default 100)
  -maxrtt float
        Maximum mean RTT for upstream queries before marking a server as dead (default 0.25)
  -memsize uint
        Memory size in MB (default 2048)
  -minlabels int
        Minimum number of labels (default 2)
  -upstream string
        Comma-delimited list of upstream servers (default "8.8.8.8:53,8.8.4.4:53")
```

Locally-served records can be defined using the `-local-rrs` switch,
followed by a path to a configuration file.

The format of this configuration file contains one record per line,
using the text representation defined in RFC 1035:

```
a.b.c.local.example.com. 86400 IN A 192.0.2.1
```
