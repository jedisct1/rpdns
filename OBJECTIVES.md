Objectives for the reverse caching DNS proxy
============================================

Non-exhaustive list of objectives, and how they are fulfilled by the
current proof-of-concept code.

Reducing latency for clients
----------------------------

### Shared cache for DNSSEC-signed and unsigned responses [TODO]

Different responses can be sent according to the `DO` bit in the
question. The cache can modify the questions to always add the `DO`
bit, cache all the records, and strip the DNSSEC-specific records when
responding to clients that didn't set the `DO` bit.

### Use EDNS0 to avoid truncated responses [IMPLEMENTED]

Clients advertise the maximum UDP payload size they support using the
EDNS0 mechanisms. Clients without EDNS0 support are assumed to only
support up to 512 bytes. Responses larger than the advertised maximum
payload size get the `TC` bit set, requiring clients to retry using TCP.

In order to reduce latency, the cache has to support EDNS0. Assuming
that a 512-bytes restriction for UDP datagrams is rarely observed for
authoritative servers, the cache can also rewrite queries to include an
`OPT` section and advertise a large payload size for its own queries
to upstream servers.

### Minimize truncated responses [IMPLEMENTED]

Responses that don't fit within the maximum payload size supported by
a client get a truncated response, whose content cannot be used by a
resolver or stub resolver.
Instead of forwarding truncated responses sent by authoritative
servers, the cache can synthesize responses on its own. In addition to
saving rounds trips, the response sent by the cache can be as short as
possible, with an empty answer section.

### Normalize queries [IMPLEMENTED]

In order to improve resistance against forgery, some clients support
the dns0x20 extension, which randomizes casing in DNS names.
This shouldn't lead to distinct cache entries. The cache should
normalize names, but respect the form initially sent by clients in its
responses.

### Coalesce identical queries [IMPLEMENTED]

Multi-threaded applications are prone to race conditions. Multiple
clients can be simultaneously waiting for the same cache entry to be filled.
In order to work around this, similar in-flight queries should be
coalesced, and the first received response should be dispatched among all
waiting clients.

### Latency guarantee [IMPLEMENTED]

Slow authoritative servers can have a huge impact on clients, even if
this is a temporary situation.
The cache can do its best to guarantee a maximum latency. If a response
that needs to be refreshed doesn't get a response within a given
time frame, the proxy can directly respond with the cached records in
order to avoid break the latency guarantee.

### Prefetching [TODO]

Cached records that are not valid any more require a new round-trip to
upstream servers, blocking clients until completion.

In order to mitigate this, the cache can schedule a query for popular
records before their expiration, and replace the cache entry as soon
as the response is received.

### Synthesize ANY queries [IMPLEMENTED]

The `ANY` query type has been deprecated for a while, but not answering
queries with the `ANY` type breaks legacy software, namely Qmail.

Cloudflare handles `ANY` queries by synthesizing responses with
`HINFO` records. We should mimic this. It doesn't violate the
protocol, doesn't break Qmail and mitigate abuses, while not requiring
any interactions with authoritative servers.

### Minimum labels count [IMPLEMENTED]

Authoritative servers our proxy will retrieve data from are unlikely
to serve records from names with a single label. These can all be
considered invalid queries sent by misconfigured clients, and don't
require round-trips to upstream servers.

In order to miminize latency, the cache can directly reply with a
synthesized `REFUSED` response.

### Blacklisting [TODO]

The vast majority of invalid queries sent to the OVH authoritative
servers are within the `access.network` zone. They spread across a
wide number of hosts, requiring many round-trips to authoritative servers.
Blacklisting these domains in the cache would avoid these unnecessary
round-trips, by allowing the cache to directly respond with `NXDOMAIN`.

Reducing the load on upstream servers
-------------------------------------

### Validation [IMPLEMENTED]

Only valid queries should be sent to authoritative servers. This
requires the cache to parse and validate the structure of the queries
instead of blindly forwarding the payload.

### Negative caching [IMPLEMENTED]

The absence of data should be cached. RFCs mandate to cache this
information for at most the value of the `minimum` TTL returned in
the `SOA` record for the zone or the closest parent zone.
While this makes sense in the context of a full-featured caching
resolver, using a fixed value is reasonable in the context of our
proxy. 600 seconds is the minimum value seen in our data set, and
provides an acceptable caching ratio.

### Negative caching for misconfigured zones [TODO]

Zones that cannot be properly retrieved from supposedly authoritative
servers should be temporarily handed over to the cache, directly
responding with `SRVFAIL` messages instead of hammering upstream servers.

### NXDOMAIN checks from root [TODO]

`NXDOMAIN` responses should cause the cache to respond with synthetic
`NXDOMAIN` responses for any names in the same zone.

This adds quite a bit of complexity to the cache, but reduces the
number of queries for non-existent names sent to upstream servers.

This is also required to invalidate cache entries for all records within
a zone.

### Concurrency control for queries sent to upstream servers [PARTLY DONE]

The cache must enforce a maximum amount of queries simultaneously sent
to upstream servers.

In order to do so, rpdns currently implements a thread pool. This
thread pool is independent from the cache: even if the pool is
exhausted, cached queries are still served to clients.

However, the concurrency for a given authoritative server cannot
exceed the number of TCP ports. Possible ways to overcome this include
having multiple source IP addresses, or leveraging TCP on servers
properly supporting pipelining.

### Per-upstream concurrency [TODO]

Concurrency control shouldn't be global, but per-authoritative server.
At least, we should use multiple thread pools.

Load balancing/failover
-----------------------

### Failover [IMPLEMENTED]

We need to keep track of authoritative servers erroring out, and remove them
from the pool.

In order to check for their availability, we should probe them in a background
process instead of wiring them to client queries, even occasionally.

### Consistent hashing [IMPLEMENTED]

In order to improve cache locality, the same questions should preferably
be always sent to the same upstream servers.

Consistent hashing limits the amount of reshuffling after servers are
being flagged as down or back up, and is a strategy the proxy can use
in order to distribute queries amount authoritative servers.

### RTT tracking [IMPLEMENTED]

In addition to a maximum number of queries and to detecting timeouts,
authoritative servers can be temporarily removed from the pool if they
happen to be too slow.

We define a maximum acceptable RTT, and consider servers whose average RTT
goes beyond the acceptable maximum as temporarily unresponsive. In
order to avoid a bias at startup time or after a server gets
reintroduced into the pool, we use a bayesian average, with a fairly
large constant.

Resilience against temporary outages
------------------------------------

### Retry over TCP when UDP fails [IMPLEMENTED]

UDP datagrams can be silently dropped. This frequently happens when
a transmit queue is full, either at the NIC level, at application
level, or at OS level.

The proxy can retry using TCP after having observed a timeout when
using UDP.

### Bypass TTL if required [IMPLEMENTED]

If authoritative servers cannot be reached for a given zone, and a
previous version of the response is available, serve that version
instead of returning a server failure.

Proxy servers are dedicated to this task. As a result, minimizing
memory usage is not a requirement. Records whose time to live has
passed should not be deleted for this sole reason. Even though they
are not fresh any more, they are kept in cache to possibly serve
future outages of authoritative servers.

Live updates
------------

### Manual refresh [TODO]

A way to manually invalidate cache entries must be available. Events
published to Redis channels are an option.

The proxy doesn't store names in a hierarchical way, and retriving the
full list of cached keys is expensive.

However, if entries are checked from the root, we may leverage serial
number to ensure that an updated zone will invalidate any records
within that zone.

### Preset list of zones [TODO]

The proxy should be aware of the list of zones served by authoritative
servers.

Redis can be used to retrieve both the whole configuration, as well as
updates.

Metrics
-------

### Live statistics [TODO]

TODO

Mitigations against attacks
---------------------------

### Hide the origin [IMPLEMENTED]

A major incentive to use a DNS proxy is to hide the actual IP
addresses of the authoritative servers, if only to help reduce the
number of open targets for DDoS attacks.

The proposed architecture naturally fits this requirement.

### Cache pollution [IMPLEMENTED]

An attacker could fill the cache with entries of little relevance, or
invalid entries, in order to reduce the cache efficiency, or partly
disrupt the service.

In order to protect against cache pollution, the proxy can use the
Adaptative Replacement Cache algorithm. This algorithm tracks both
recently used and frequently used entries.

Thus, a significant amount of new entries will not have a perceptible
impact on frequently asked DNS questions.

### Fragment attacks [TODO]

Fragments attacks represent an interesting way to poison a DNS cache.
They apply to recursive resolvers, as well as to our reverse DNS proxy.
Our proxy should drop fragmented packets.

### Protect upstreams against resource exhaustion [IMPLEMENTED]

The cache shouldn't sent more queries to authoritative servers than
they can handle.

Using a fixed-size thread pool is a way to achieve this, as well as
other techniques described above, such as suspending the traffic to a
server if the average RTT becomes too high.

### Response Rate Limiting [IMPLEMENTED]

If the global RTT becomes too high, either the infrastructure is
suffering a major incident, or the authoritative servers are under
attack.

In this situation, the proxy should do its best to answer legitimate
traffic, and block malicious traffic, which is likely to be coming
from spoofed source IP addresses.

The best known defense against this is to send truncated responses to
some queries, forcing a retry using TCP, as well as dropping some
responses in order to force resolvers without TCP support to retry.

When upstream servers are overloaded, our proxy can thus:
- Answer 50% of the queries normally
- Answer 25% of the queries with a truncated response
- Ignore 25% of the queries - Legitimate stub resolvers will
automatically perform a retry.

This gives a chance to the authoritative servers to recover instead of
possibly aggravating the situation.

### Minimal ANY response [IMPLEMENTED]

Queries for the `ANY` type are consistently being used in DNS
amplification attacks.

Synthesize minimal responses that don't break legacy software instead
of returning possibly huge responses to spoofed IP addresses.

### Limit the number of in-flight TCP connections [TODO]

Keeping TCP connections open consumes file descriptors, memory and
threads.

The proxy should enforce a short timeout, and recycle connections from
a fixed-size pool. An exhausted pool should be prevent queries sent
using UDP.

### Client-specific RRL [TODO]

Detect an usual amount of responses sent to a single client IP or
network, and activate RRL mitigations to prevent the proxy from being
abused for DDoS attacks.
