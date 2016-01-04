RPDNS
=====

RPDNS is a crude caching reverse DNS proxy.

```
[Clients] -> [RPDNS] -> [authoritative servers]
```

RPDNS accepts DNS queries, and responds from its own cache or after
forwarding them to a set of authoritative servers.

Although queries can be forwarded to recursive servers as well, RPDNS
itself does not perform any recursion. Its main purpose is to reduce
the load on authoritative servers.

Features
--------

* EDNS0 support. Forwarded queries are rewritten in order to accept
large payloads over UDP, independently from the payload size
advertised by the client.
* ANY queries are answered directly as a synthesized HINFO record.
* TCP and UDP support; support for truncated responses
* ARC-based DNS cache
* DNSSEC support
* Basic failover/load balancing with consistent hashing


Install
-------

```bash
$ go get github.com/jedisct1/rpdns
```

Usage
-----
```
  -cachesize int
    	Cache size (default 10000000)
  -listen string
    	Address to listen to (TCP and UDP) (default ":53")
  -maxclients uint
    	Maximum number of simultaneous clients (default 10000)
  -maxrtt float
    	Maximum mean RTT for upstream queries before marking a server as dead (default 0.25)
  -memsize uint
    	Memory size in MB (default=1GB) (default 1024)
  -minlabels int
    	Minimum number of labels (default=2) (default 2)
  -upstream string
    	Comma-delimited list of upstream servers (default "8.8.8.8:53,8.8.4.4:53")
```
