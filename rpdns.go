package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dchest/siphash"
	"github.com/hashicorp/golang-lru"
	"github.com/miekg/dns"
)

const (
	// BayesianAverageC Constant for the Bayesian average for the RTT
	BayesianAverageC = 10
	// MaxFailures Maximum number of unanswered queries before a server is marked as dead for VacuumPeriod
	MaxFailures = 10
	// MinTTL Minimum TTL
	MinTTL = 60
	// MaxTTL Maximum TTL
	MaxTTL = 604800
	// VacuumPeriod Vacuum period in seconds
	VacuumPeriod = 30
)

// SipHashKey SipHash secret key
type SipHashKey struct {
	k1 uint64
	k2 uint64
}

// UpstreamServer Upstream server
type UpstreamServer struct {
	addr     string
	failures uint
	offline  bool
}

// UpstreamServers List of upstream servers
type UpstreamServers struct {
	lock    sync.RWMutex
	servers []UpstreamServer
	live    []string
}

// UpstreamRTT Keep track of the mean RTT
type UpstreamRTT struct {
	lock  sync.Mutex
	RTT   float64
	count float64
}

var (
	address            = flag.String("listen", ":53", "Address to listen to (TCP and UDP)")
	upstreamServersStr = flag.String("upstream", "8.8.8.8:53,8.8.4.4:53", "Comma-delimited list of upstream servers")
	upstreamServers    *UpstreamServers
	cacheSize          = flag.Int("cachesize", 10000000, "Cache size")
	memSize            = flag.Uint64("memsize", 1*1024, "Memory size in MB")
	minLabelsCount     = flag.Int("minlabels", 2, "Minimum number of labels")
	cache              *lru.ARCCache
	sipHashKey         = SipHashKey{k1: 0, k2: 0}
	pending            = uint32(0)
	maxClients         = flag.Uint("maxclients", 10000, "Maximum number of simultaneous clients")
	maxRTT             = flag.Float64("maxrtt", 0.25, "Maximum mean RTT for upstream queries before marking a server as dead")
	upstreamRtt        UpstreamRTT
)

func parseUpstreamServers(str string) (*UpstreamServers, error) {
	servers := []UpstreamServer{}
	live := []string{}
	for _, addr := range strings.Split(str, ",") {
		server := UpstreamServer{addr: addr}
		servers = append(servers, server)
		live = append(live, addr)
	}
	res := UpstreamServers{servers: servers, live: live}
	return &res, nil
}

func randUint64() uint64 {
	buf := make([]byte, 8)
	length, err := rand.Read(buf)
	if err != nil || length != len(buf) {
		log.Fatal("RNG failure")
	}
	return binary.LittleEndian.Uint64(buf)
}

func main() {
	flag.Parse()
	*memSize *= 1024 * 1024
	if *cacheSize < 2 {
		log.Fatal("Cache size too small")
	}
	cache, _ = lru.NewARC(*cacheSize)
	upstreamServers, _ = parseUpstreamServers(*upstreamServersStr)
	sipHashKey = SipHashKey{k1: randUint64(), k2: randUint64()}
	fmt.Println("RPDNS")
	dns.HandleFunc(".", route)
	udpServer := &dns.Server{Addr: *address, Net: "udp"}
	tcpServer := &dns.Server{Addr: *address, Net: "tcp"}
	go func() {
		log.Fatal(udpServer.ListenAndServe())
	}()
	go func() {
		log.Fatal(tcpServer.ListenAndServe())
	}()
	vacuumThread()
}

// CacheKey Key for a cache entry
type CacheKey struct {
	Name   string `dns:"cdomain-name"`
	Qtype  uint16
	DNSSEC bool
}

// CacheVal Value for a cache entry
type CacheVal struct {
	ValidUntil time.Time
	Response   *dns.Msg
}

func getKey(req *dns.Msg) (*CacheKey, error) {
	questions := req.Question
	if len(questions) != 1 {
		return nil, errors.New("Invalid number of questions")
	}
	question := questions[0]
	if question.Qclass != dns.ClassINET {
		return nil, errors.New("Unsupported question class")
	}
	if dns.CountLabel(question.Name) < *minLabelsCount {
		return nil, errors.New("Not enough labels")
	}
	dnssec := false
	for _, extra := range req.Extra {
		if extra.Header().Rrtype == dns.TypeOPT {
			dnssec = extra.(*dns.OPT).Do()
		}
	}
	CacheKey := CacheKey{Name: strings.ToLower(question.Name),
		Qtype: question.Qtype, DNSSEC: dnssec}
	return &CacheKey, nil
}

func getMaxPayloadSize(req *dns.Msg) uint16 {
	opt := req.IsEdns0()
	if opt == nil {
		return dns.MinMsgSize
	}
	maxPayloadSize := opt.UDPSize()
	if maxPayloadSize < dns.MinMsgSize {
		maxPayloadSize = dns.MinMsgSize
	}
	return maxPayloadSize
}

func pickUpstream(req *dns.Msg) (*string, error) {
	name := strings.ToLower(req.Question[0].Name)
	h := siphash.Hash(sipHashKey.k1, sipHashKey.k2, []byte(name))
	upstreamServers.lock.RLock()
	liveCount := uint64(len(upstreamServers.live))
	if liveCount <= 0 {
		upstreamServers.lock.RUnlock()
		return nil, errors.New("All upstream servers are down")
	}
	i := h / (math.MaxUint64 / liveCount)
	if i >= liveCount {
		i = liveCount - 1
	}
	res := upstreamServers.live[i]
	upstreamServers.lock.RUnlock()
	return &res, nil
}

func markFailed(addr string) {
	upstreamServers.lock.Lock()
	defer upstreamServers.lock.Unlock()
	for i, server := range upstreamServers.servers {
		if server.addr != addr {
			continue
		}
		if server.offline {
			return
		}
		upstreamServers.servers[i].failures++
		if upstreamServers.servers[i].failures < MaxFailures {
			return
		}
		break
	}
	servers := upstreamServers.servers
	live := []string{}
	for i, server := range upstreamServers.servers {
		if server.addr == addr {
			servers[i].offline = true
		} else if server.offline == false {
			live = append(live, server.addr)
		}
	}
	upstreamServers.servers = servers
	upstreamServers.live = live
	log.Printf("[%v] is unresponsive", addr)
}

func resetRTT() {
	upstreamRtt.lock.Lock()
	defer upstreamRtt.lock.Unlock()
	upstreamRtt.count = 0.0
	upstreamRtt.RTT = 0.0
}

func resetUpstreamServers() {
	upstreamServers.lock.Lock()
	defer upstreamServers.lock.Unlock()
	servers := upstreamServers.servers
	if len(servers) == len(upstreamServers.live) {
		return
	}
	live := []string{}
	for i, server := range upstreamServers.servers {
		servers[i].failures = 0
		servers[i].offline = false
		live = append(live, server.addr)
	}
	upstreamServers.servers = servers
	upstreamServers.live = live
	resetRTT()
}

func syncResolve(req *dns.Msg) (*dns.Msg, time.Duration, error) {
	curPending := atomic.AddUint32(&pending, uint32(1))
	defer atomic.AddUint32(&pending, ^uint32(0))
	if uint(curPending) > *maxClients {
		return nil, 0, errors.New("Too many clients")
	}
	addr, err := pickUpstream(req)
	if err != nil {
		return nil, 0, err
	}
	client := &dns.Client{Net: "udp"}
	client.SingleInflight = true
	resolved, rtt, err := client.Exchange(req, *addr)
	if resolved.Truncated {
		client = &dns.Client{Net: "tcp"}
		client.SingleInflight = true
		resolved, rtt, err = client.Exchange(req, *addr)
	}
	if err != nil {
		markFailed(*addr)
		return nil, 0, err
	}
	upstreamRtt.lock.Lock()
	upstreamRtt.count++
	upstreamRtt.RTT += rtt.Seconds()
	meanRTT := upstreamRtt.RTT / (upstreamRtt.count + BayesianAverageC)
	upstreamRtt.lock.Unlock()
	if meanRTT > *maxRTT {
		markFailed(*addr)
	}
	return resolved, rtt, nil
}

func resolve(req *dns.Msg, dnssec bool) (*dns.Msg, error) {
	extra2 := []dns.RR{}
	for _, extra := range req.Extra {
		if extra.Header().Rrtype != dns.TypeOPT {
			extra2 = append(extra2, extra)
		}
	}
	req.Extra = extra2
	req.SetEdns0(dns.MaxMsgSize, dnssec)
	resolved, _, err := syncResolve(req)
	if err != nil {
		return nil, err
	}
	resolved.Compress = true
	return resolved, nil
}

func getMinTTL(resp *dns.Msg) time.Duration {
	ttl := uint32(MaxTTL)
	for _, rr := range resp.Answer {
		if rr.Header().Ttl < ttl {
			ttl = rr.Header().Ttl
		}
	}
	if ttl < MinTTL {
		ttl = MaxTTL
	}
	return time.Duration(ttl) * time.Second
}

func sendTruncated(w dns.ResponseWriter, msgHdr dns.MsgHdr) {
	emptyResp := new(dns.Msg)
	emptyResp.MsgHdr = msgHdr
	emptyResp.Truncated = true
	w.WriteMsg(emptyResp)
}

func vacuumThread() {
	for {
		time.Sleep(VacuumPeriod * time.Second)
		resetUpstreamServers()
		memStats := new(runtime.MemStats)
		runtime.ReadMemStats(memStats)
		if memStats.Alloc > (*memSize)*1024*1024 {
			cache.Purge()
		}
	}
}

func failWithRcode(w dns.ResponseWriter, r *dns.Msg, rCode int) {
	m := new(dns.Msg)
	m.SetRcode(r, rCode)
	w.WriteMsg(m)
}

func handleSpecialNames(w dns.ResponseWriter, req *dns.Msg) bool {
	question := req.Question[0]
	if question.Qtype != dns.TypeANY {
		return false
	}
	m := new(dns.Msg)
	m.Id = req.Id
	hinfo := new(dns.HINFO)
	hinfo.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeHINFO,
		Class: dns.ClassINET, Ttl: 86400}
	hinfo.Cpu = "ANY is not supported any more"
	hinfo.Os = "See draft-jabley-dnsop-refuse-any"
	m.Answer = []dns.RR{hinfo}
	w.WriteMsg(m)
	return true
}

func route(w dns.ResponseWriter, req *dns.Msg) {
	keyP, err := getKey(req)
	if err != nil {
		failWithRcode(w, req, dns.RcodeRefused)
		return
	}
	if handleSpecialNames(w, req) {
		return
	}
	maxPayloadSize := getMaxPayloadSize(req)
	var resp *dns.Msg
	cacheValP, _ := cache.Get(*keyP)
	if cacheValP != nil {
		cacheVal := cacheValP.(CacheVal)
		remaining := -time.Since(cacheVal.ValidUntil)
		if remaining > 0 {
			resp = cacheVal.Response.Copy()
			resp.Id = req.Id
			resp.Question = req.Question
		}
	}
	if resp == nil {
		resp, err = resolve(req, keyP.DNSSEC)
		if err != nil {
			dns.HandleFailed(w, req)
			return
		}
		validUntil := time.Now().Add(getMinTTL(resp))
		cache.Add(*keyP, CacheVal{ValidUntil: validUntil, Response: resp})
	}
	packed, _ := resp.Pack()
	packedLen := len(packed)
	if uint16(packedLen) > maxPayloadSize {
		sendTruncated(w, resp.MsgHdr)
	} else {
		w.WriteMsg(resp)
	}
}
