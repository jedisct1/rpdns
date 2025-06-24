package main

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dchest/siphash"
	lru "github.com/hashicorp/golang-lru"
	"github.com/miekg/dns"
)

const (
	// BayesianAverageC Constant for the Bayesian average for the RTT
	BayesianAverageC = 100
	// MaxUDPBufferSize UDP buffer size
	MaxUDPBufferSize = 16 * 1024 * 1024
	// NegCacheMinTTL Minimum TTL for the negative cache
	NegCacheMinTTL = 600
	// MinTTL Minimum TTL
	MinTTL = 60
	// MaxTTL Maximum TTL
	MaxTTL = 604800
	// VacuumPeriod Vacuum period in seconds
	VacuumPeriod = 60 * time.Second
)

// SipHashKey SipHash secret key
type SipHashKey struct {
	k0 uint64
	k1 uint64
}

// UpstreamServer Upstream server
type UpstreamServer struct {
	addr     string
	failures *uint64
	offline  *atomic.Bool
}

// UpstreamServers List of upstream servers
type UpstreamServers struct {
	mu      sync.RWMutex
	servers []UpstreamServer
	live    []string
}

// UpstreamRTT Keep track of the mean RTT
type UpstreamRTT struct {
	mu    sync.Mutex
	rtt   float64
	count float64
}

// QueuedResponse Response to an asynchronous query
type QueuedResponse struct {
	resolved *dns.Msg
	rtt      time.Duration
	err      error
}

// QueuedRequest Asynchronous DNS request
type QueuedRequest struct {
	ts           time.Time
	req          *dns.Msg
	responseChan chan QueuedResponse
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

// LocalRR Structure containing a locally served record
type LocalRR struct {
	Name string `dns:"cdomain-name"`
	RR   *dns.RR
}

var (
	address            = flag.String("listen", ":53", "Address to listen to (TCP and UDP)")
	upstreamServersStr = flag.String("upstream", "8.8.8.8:53,8.8.4.4:53", "Comma-delimited list of upstream servers")
	upstreamServers    *UpstreamServers
	cacheSize          = flag.Int("cachesize", 2*1024*1024*1024/2048, "Number of cached responses")
	memSize            = flag.Uint64("memsize", 2*1024, "Memory size in MB")
	minLabelsCount     = flag.Int("minlabels", 2, "Minimum number of labels")
	maxFailures        = flag.Uint("maxfailures", 100, "Number of unanswered queries before a server is temporarily considered offline")
	debug              = flag.Bool("debug", false, "Debug mode")
	cache              *lru.ARCCache
	sipHashKey         = SipHashKey{k0: 0, k1: 0}
	maxClients         = flag.Uint("maxclients", 1000, "Maximum number of simultaneous clients")
	maxRTT             = flag.Float64("maxrtt", 0.25, "Maximum mean RTT for upstream queries before marking a server as dead")
	localRRSFile       = flag.String("local-rrs", "", "Config files with local records")
	upstreamRtt        UpstreamRTT
	resolverRing       chan QueuedRequest
	globalTimeout      = 2 * time.Second
	slip               uint32
	udpClient          dns.Client
	tcpClient          dns.Client
	localRRS           []LocalRR
)

func parseUpstreamServers(str string) (*UpstreamServers, error) {
	servers := []UpstreamServer{}
	live := []string{}
	for _, addr := range strings.Split(str, ",") {
		var failures uint64
		server := UpstreamServer{
			addr:     addr,
			failures: &failures,
			offline:  &atomic.Bool{},
		}
		servers = append(servers, server)
		live = append(live, addr)
	}
	res := UpstreamServers{servers: servers, live: live}
	log.Printf("Configured upstream servers: %v\n", live)
	return &res, nil
}

func randUint64() uint64 {
	buf := make([]byte, 8)
	_, err := rand.Read(buf)
	if err != nil {
		log.Fatal("RNG failure:", err)
	}
	return binary.LittleEndian.Uint64(buf)
}

func parseLocalRRSFile(file string) {
	if file == "" {
		return
	}
	fp, err := os.Open(file)
	if err != nil {
		log.Fatalf("failed to open local RRS file: %v", err)
	}
	defer fp.Close()
	scanner := bufio.NewScanner(fp)
	localRRS = make([]LocalRR, 0)
	for scanner.Scan() {
		s := scanner.Text()
		rr, err := dns.NewRR(s)
		if err != nil {
			log.Fatalf("failed to parse RR %q: %v", s, err)
		}
		if rr == nil {
			continue
		}
		localRR := LocalRR{Name: strings.ToLower(rr.Header().Name), RR: &rr}
		localRRS = append(localRRS, localRR)
	}
}

func main() {
	flag.Parse()
	*memSize *= 1024 * 1024
	if *cacheSize < 2 {
		log.Fatal("Cache size too small")
	}
	parseLocalRRSFile(*localRRSFile)
	var err error
	cache, err = lru.NewARC(*cacheSize)
	if err != nil {
		log.Fatal("Failed to create cache:", err)
	}
	upstreamServers, err = parseUpstreamServers(*upstreamServersStr)
	if err != nil {
		log.Fatal("Failed to parse upstream servers:", err)
	}
	sipHashKey = SipHashKey{k0: randUint64(), k1: randUint64()}
	resolverRing = make(chan QueuedRequest, *maxClients)
	globalTimeout = time.Duration((*maxRTT) * 3.0 * float64(time.Second))
	udpClient = dns.Client{Net: "udp", DialTimeout: globalTimeout, ReadTimeout: globalTimeout, WriteTimeout: globalTimeout, SingleInflight: true}
	tcpClient = dns.Client{Net: "tcp", DialTimeout: globalTimeout, ReadTimeout: globalTimeout, WriteTimeout: globalTimeout, SingleInflight: true}
	probeUpstreamServers(true)
	upstreamServers.mu.Lock()
	log.Printf("Live upstream servers: %v\n", upstreamServers.live)
	upstreamServers.mu.Unlock()
	for i := uint(0); i < *maxClients; i++ {
		go resolverThread()
	}
	dns.HandleFunc(".", route)
	defer dns.HandleRemove(".")
	udpServer := &dns.Server{Addr: *address, Net: "udp"}
	defer udpServer.Shutdown()
	udpAddr, err := net.ResolveUDPAddr(udpServer.Net, udpServer.Addr)
	if err != nil {
		log.Fatalf("failed to resolve UDP address: %v", err)
	}
	udpPacketConn, err := net.ListenUDP(udpServer.Net, udpAddr)
	if err != nil {
		log.Fatalf("failed to listen on UDP: %v", err)
	}
	udpServer.PacketConn = udpPacketConn
	if err := udpPacketConn.SetReadBuffer(MaxUDPBufferSize); err != nil {
		log.Printf("Failed to set UDP read buffer: %v", err)
	}
	if err := udpPacketConn.SetWriteBuffer(MaxUDPBufferSize); err != nil {
		log.Printf("Failed to set UDP write buffer: %v", err)
	}

	tcpServer := &dns.Server{Addr: *address, Net: "tcp"}
	defer tcpServer.Shutdown()
	tcpAddr, err := net.ResolveTCPAddr(tcpServer.Net, tcpServer.Addr)
	if err != nil {
		log.Fatalf("failed to resolve TCP address: %v", err)
	}
	tcpListener, err := net.ListenTCP(tcpServer.Net, tcpAddr)
	if err != nil {
		log.Fatalf("failed to listen on TCP: %v", err)
	}
	tcpServer.Listener = tcpListener
	go func() {
		if err := udpServer.ActivateAndServe(); err != nil {
			log.Fatalf("UDP server error: %v", err)
		}
	}()
	go func() {
		if err := tcpServer.ActivateAndServe(); err != nil {
			log.Fatalf("TCP server error: %v", err)
		}
	}()
	fmt.Println("Ready")
	vacuumThread()
}

func getKey(req *dns.Msg) (*CacheKey, error) {
	questions := req.Question
	if len(questions) != 1 {
		return nil, errors.New("invalid number of questions")
	}
	question := questions[0]
	if question.Qclass != dns.ClassINET {
		return nil, errors.New("unsupported question class")
	}
	if dns.CountLabel(question.Name) < *minLabelsCount {
		return nil, errors.New("not enough labels")
	}
	dnssec := false
	for _, extra := range req.Extra {
		if extra.Header().Rrtype == dns.TypeOPT {
			dnssec = extra.(*dns.OPT).Do()
		}
	}
	CacheKey := CacheKey{
		Name:  strings.ToLower(question.Name),
		Qtype: question.Qtype, DNSSEC: dnssec,
	}
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
	h := siphash.Hash(sipHashKey.k0, sipHashKey.k1, []byte(name))
	upstreamServers.mu.RLock()
	defer upstreamServers.mu.RUnlock()
	liveCount := uint64(len(upstreamServers.live))
	if liveCount <= 0 {
		return nil, errors.New("all upstream servers are down")
	}
	i := h / (math.MaxUint64 / liveCount)
	if i >= liveCount {
		i = liveCount - 1
	}
	res := upstreamServers.live[i]
	return &res, nil
}

func markFailed(addr string) {
	upstreamServers.mu.Lock()
	defer upstreamServers.mu.Unlock()
	for i := range upstreamServers.servers {
		if upstreamServers.servers[i].addr != addr {
			continue
		}
		if upstreamServers.servers[i].offline.Load() {
			return
		}
		newFailures := atomic.AddUint64(upstreamServers.servers[i].failures, 1)
		if newFailures < uint64(*maxFailures) {
			return
		}
		break
	}
	if len(upstreamServers.live) <= 1 {
		resetUpstreamServersNoLock()
		return
	}
	servers := upstreamServers.servers
	live := []string{}
	for i := range upstreamServers.servers {
		if upstreamServers.servers[i].addr == addr {
			servers[i].offline.Store(true)
		} else if !upstreamServers.servers[i].offline.Load() {
			live = append(live, upstreamServers.servers[i].addr)
		}
	}
	upstreamServers.servers = servers
	upstreamServers.live = live
}

func resetRTT() {
	upstreamRtt.mu.Lock()
	defer upstreamRtt.mu.Unlock()
	upstreamRtt.count = 0.0
	upstreamRtt.rtt = 0.0
}

func resetUpstreamServersNoLock() {
	servers := upstreamServers.servers
	if len(servers) == len(upstreamServers.live) {
		return
	}
	live := []string{}
	for i := range upstreamServers.servers {
		atomic.StoreUint64(servers[i].failures, 0)
		servers[i].offline.Store(false)
		live = append(live, upstreamServers.servers[i].addr)
	}
	upstreamServers.servers = servers
	upstreamServers.live = live
	resetRTT()
}

func resetUpstreamServers() {
	upstreamServers.mu.Lock()
	resetUpstreamServersNoLock()
	upstreamServers.mu.Unlock()
}

func probeUpstreamServers(verbose bool) {
	upstreamServers.mu.Lock()
	servers := upstreamServers.servers
	upstreamServers.mu.Unlock()
	live := []string{}
	req := new(dns.Msg)
	req.SetQuestion(".", dns.TypeSOA)
	for i := range upstreamServers.servers {
		server := &upstreamServers.servers[i]
		if !server.offline.Load() && atomic.LoadUint64(server.failures) > 0 {
			if verbose {
				log.Printf("[%v] assumed to be online", server.addr)
			}
			live = append(live, server.addr)
			continue
		}
		if verbose {
			log.Printf("Probing [%v] ...", server.addr)
		}
		_, rtt, err := udpClient.Exchange(req, server.addr)
		if err == nil && rtt.Seconds() < *maxRTT {
			servers[i].offline.Store(false)
			atomic.StoreUint64(servers[i].failures, 0)
			live = append(live, server.addr)
			if verbose {
				log.Printf("working, rtt=%v\n", rtt)
			}
		} else {
			if verbose {
				log.Println(err)
			}
		}
	}
	upstreamServers.mu.Lock()
	upstreamServers.servers = servers
	upstreamServers.live = live
	upstreamServers.mu.Unlock()
	resetRTT()
}

func syncResolve(req *dns.Msg) (*dns.Msg, time.Duration, error) {
	addr, err := pickUpstream(req)
	if err != nil {
		return nil, 0, err
	}
	resolved, rtt, err := udpClient.Exchange(req, *addr)
	if err != nil || (resolved != nil && resolved.Truncated) {
		resolved, rtt, err = tcpClient.Exchange(req, *addr)
	}
	if err != nil {
		markFailed(*addr)
		return nil, 0, err
	}
	upstreamRtt.mu.Lock()
	upstreamRtt.count++
	upstreamRtt.rtt += rtt.Seconds()
	meanRTT := upstreamRtt.rtt / (upstreamRtt.count + BayesianAverageC)
	upstreamRtt.mu.Unlock()
	if meanRTT > *maxRTT {
		markFailed(*addr)
	}
	return resolved, rtt, nil
}

func resolverThread() {
	for {
		queuedRequest := <-resolverRing
		if time.Since(queuedRequest.ts).Seconds() > *maxRTT {
			response := QueuedResponse{resolved: nil, rtt: 0, err: errors.New("request too old")}
			queuedRequest.responseChan <- response
			close(queuedRequest.responseChan)
			atomic.AddUint32(&slip, 1)
			continue
		}
		resolved, rtt, err := syncResolve(queuedRequest.req)
		response := QueuedResponse{resolved: resolved, rtt: rtt, err: err}
		queuedRequest.responseChan <- response
		close(queuedRequest.responseChan)
	}
}

func resolveViaResolverThreads(req *dns.Msg) (*dns.Msg, time.Duration, error) {
	responseChan := make(chan QueuedResponse)
	queuedRequest := QueuedRequest{ts: time.Now(), req: req, responseChan: responseChan}
	for queued := false; queued == false; {
		select {
		case resolverRing <- queuedRequest:
			queued = true
		default:
			old := <-resolverRing
			evictedResponse := QueuedResponse{resolved: nil, rtt: 0, err: errors.New("evicted")}
			old.responseChan <- evictedResponse
		}
	}
	response := <-responseChan
	if response.err != nil {
		return nil, response.rtt, response.err
	}
	return response.resolved, response.rtt, nil
}

func resolve(req *dns.Msg, dnssec bool) (*dns.Msg, error) {
	extra2 := []dns.RR{}
	for _, extra := range req.Extra {
		if extra.Header().Rrtype != dns.TypeOPT {
			extra2 = append(extra2, extra)
		}
	}
	req.Extra = extra2
	req.SetEdns0(dns.DefaultMsgSize, dnssec)
	resolved, _, err := resolveViaResolverThreads(req)
	if err != nil {
		return nil, err
	}
	resolved.Compress = true
	return resolved, nil
}

func getMinTTL(resp *dns.Msg) time.Duration {
	if len(resp.Answer) <= 0 {
		return time.Duration(NegCacheMinTTL) * time.Second
	}
	ttl := uint32(MaxTTL)
	for _, rr := range resp.Answer {
		if rr.Header().Ttl < ttl {
			ttl = rr.Header().Ttl
		}
	}
	if ttl < MinTTL {
		ttl = MinTTL
	}
	return time.Duration(ttl) * time.Second
}

func sendTruncated(w dns.ResponseWriter, msgHdr dns.MsgHdr) {
	emptyResp := new(dns.Msg)
	emptyResp.MsgHdr = msgHdr
	emptyResp.Response = true
	if _, isTCP := w.RemoteAddr().(*net.TCPAddr); isTCP {
		dns.HandleFailed(w, emptyResp)
		return
	}
	emptyResp.Truncated = true
	if err := w.WriteMsg(emptyResp); err != nil {
		if *debug {
			log.Printf("Failed to write truncated response: %v", err)
		}
	}
}

func vacuumThread() {
	for {
		time.Sleep(VacuumPeriod)
		atomic.StoreUint32(&slip, 0)
		probeUpstreamServers(*debug)
		memStats := new(runtime.MemStats)
		runtime.ReadMemStats(memStats)
		if memStats.Alloc > *memSize {
			cache.Purge()
		}
	}
}

func failWithRcode(w dns.ResponseWriter, r *dns.Msg, rCode int) {
	m := new(dns.Msg)
	m.SetRcode(r, rCode)
	if err := w.WriteMsg(m); err != nil {
		if *debug {
			log.Printf("Failed to write error response: %v", err)
		}
	}
}

func handleSpecialNames(w dns.ResponseWriter, req *dns.Msg) bool {
	question := req.Question[0]
	nameLC := strings.ToLower(question.Name)
	for _, localRR := range localRRS {
		if nameLC == localRR.Name {
			m := new(dns.Msg)
			m.Id = req.Id
			m.Answer = []dns.RR{*localRR.RR}
			m.Response = true
			if err := w.WriteMsg(m); err != nil {
				if *debug {
					log.Printf("Failed to write local RR response: %v", err)
				}
			}
			return true
		}
	}
	if question.Qtype != dns.TypeANY {
		return false
	}
	m := new(dns.Msg)
	m.Id = req.Id
	hinfo := new(dns.HINFO)
	hinfo.Hdr = dns.RR_Header{
		Name: question.Name, Rrtype: dns.TypeHINFO,
		Class: dns.ClassINET, Ttl: 86400,
	}
	hinfo.Cpu = "ANY is not supported any more"
	hinfo.Os = "See draft-jabley-dnsop-refuse-any"
	m.Answer = []dns.RR{hinfo}
	m.Response = true
	if err := w.WriteMsg(m); err != nil {
		if *debug {
			log.Printf("Failed to write ANY response: %v", err)
		}
	}
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
	if *debug {
		question := req.Question[0]
		cachedStr := ""
		if resp != nil {
			cachedStr = " (cached)"
		}
		log.Printf("%v\t%v %v%v\n", w.RemoteAddr(), question.Name, dns.TypeToString[question.Qtype], cachedStr)
	}
	if resp == nil {
		slipValue := atomic.LoadUint32(&slip)
		if slipValue > 0 && slipValue%2 == 0 {
			atomic.CompareAndSwapUint32(&slip, slipValue, slipValue+1)
			if slipValue%4 == 0 {
				sendTruncated(w, req.MsgHdr)
			} else {
				w.Close()
			}
			return
		}
	}
	if resp == nil {
		resp, err = resolve(req, keyP.DNSSEC)
		if err == nil {
			validUntil := time.Now().Add(getMinTTL(resp))
			cache.Add(*keyP, CacheVal{ValidUntil: validUntil, Response: resp})
		} else {
			if cacheValP == nil {
				w.Close()
				return
			}
			cacheVal := cacheValP.(CacheVal)
			resp = cacheVal.Response.Copy()
			resp.Id = req.Id
			resp.Question = req.Question
		}
	}
	packed, err := resp.Pack()
	if err != nil {
		w.Close()
		return
	}
	packedLen := len(packed)
	if uint16(packedLen) > maxPayloadSize {
		sendTruncated(w, resp.MsgHdr)
	} else {
		if err := w.WriteMsg(resp); err != nil {
			if *debug {
				log.Printf("Failed to write response: %v", err)
			}
		}
	}
}
