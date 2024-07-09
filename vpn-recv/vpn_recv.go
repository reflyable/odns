// Package whoami implements a plugin that returns details about the resolving
// querying it.
package vpn_recv

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
	"golang.org/x/net/publicsuffix"
)

const name = "vpn-recv"

var ctx1 = context.Background()
var log = clog.NewWithPlugin("vpn_recv")

type ResponseReverter struct {
	dns.ResponseWriter
	start            time.Time
	originalQuestion dns.Question
	mask             uint32
}

// NewResponseReverter returns a pointer to a new ResponseReverter.
func NewResponseReverter(w dns.ResponseWriter, r *dns.Msg, ipkey uint32, start time.Time) *ResponseReverter {
	return &ResponseReverter{
		start:            start,
		ResponseWriter:   w,
		originalQuestion: r.Question[0],
		mask:             ipkey,
	}
}

// WriteMsg records the status code and calls the underlying ResponseWriter's WriteMsg method.
func (r *ResponseReverter) WriteMsg(res1 *dns.Msg) error {
	log.Debug(res1.String())
	res := res1.Copy()
	res.Compress = true
	res.Question[0] = r.originalQuestion

	for i := len(res.Answer) - 1; i >= 0; i-- {
		rr := res.Answer[i]
		if rr.Header().Rrtype == dns.TypeA {
			rr.Header().Name = r.originalQuestion.Name
			ip := make(net.IP, net.IPv4len)
			binary.BigEndian.PutUint32(ip, binary.BigEndian.Uint32(rr.(*dns.A).A.To4())^r.mask)
			rr.(*dns.A).A = ip
		} else {
			res.Answer = append(res.Answer[:i], res.Answer[i+1:]...)
		}
	}
	if len(res.Answer) == 0 {
		res.Rcode = dns.RcodeServerFailure
	}
	res.Ns = nil
	res.Extra = nil
	res.RecursionDesired = false
	res.RecursionAvailable = false
	res.Authoritative = true

	state := request.Request{W: r.ResponseWriter, Req: res}
	state.SizeAndDo(res)
	RequestDuration.Observe(time.Since(r.start).Seconds())
	return r.ResponseWriter.WriteMsg(res)
}

// Write is a wrapper that records the size of the message that gets written.
func (r *ResponseReverter) Write(buf []byte) (int, error) {
	n, err := r.ResponseWriter.Write(buf)
	return n, err
}

// Whoami is a plugin that returns your IP address, port and the protocol used for connecting
// to CoreDNS.
type vpn_recv struct {
	Next       plugin.Handler
	privateKey *ecdsa.PrivateKey
	rdb        *redis.Client
	domain     string
	local      string
}

// ServeDNS implements the plugin.Handler interface.
func (vr vpn_recv) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	prefix, e := strings.CutSuffix(r.Question[0].Name, vr.domain)
	if !e {
		return plugin.NextOrFailure(vr.Name(), vr.Next, ctx, w, r)
	}
	if r.Question[0].Qtype == dns.TypeTXT {
		res := new(dns.Msg).SetReply(r)
		r := new(dns.TXT)
		r.Hdr = dns.RR_Header{Name: vr.domain, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}
		cont := elliptic.MarshalCompressed(vr.privateKey.PublicKey.Curve, vr.privateKey.PublicKey.X, vr.privateKey.PublicKey.Y)

		r.Txt = []string{base64.StdEncoding.EncodeToString(cont) + vr.domain}
		log.Debugf("%s %v\n", r.Txt, cont)
		res.Answer = append(res.Answer, r)
		w.WriteMsg(res)
		return dns.RcodeSuccess, nil
	} else if r.Question[0].Qtype != dns.TypeA {
		return plugin.NextOrFailure(vr.Name(), vr.Next, ctx, w, r)
	}
	count := strings.Count(prefix, ".")
	prefix = strings.ReplaceAll(prefix, ".", "")
	if strings.Count(prefix, "0") != len(prefix) && prefix[0] != '0' {
		state := request.Request{W: w, Req: r}
		ns := new(dns.NS)
		ns.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}
		ns.Ns = "90ns" + strconv.Itoa(count) + "." + vr.domain
		ref := new(dns.A)
		ref.Hdr = dns.RR_Header{Name: ns.Ns, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}
		ref.A = net.ParseIP(state.LocalIP())
		// log.Println("Qname is not complete!")

		res := new(dns.Msg).SetRcode(r, dns.RcodeSuccess)
		if len(prefix) < 10 && len(prefix) >= 4 && strings.ToLower(prefix)[:4] == "90ns" {
			res.Answer = []dns.RR{ref}
		} else {
			res.Answer = nil
			res.Ns = []dns.RR{ns}
			res.Extra = []dns.RR{ref}
		}
		state.SizeAndDo(res)
		w.WriteMsg(res)
		return dns.RcodeSuccess, nil
	}
	prefix = strings.ToUpper(prefix[1:])
	start := time.Now()

	log.Debug("RECV DNS Recv: ", r.Question[0].Name)

	log.Debug("RECV DNS Entry: ", prefix)
	ciphertxt, err := base32.StdEncoding.WithPadding('0').DecodeString(prefix)
	if err != nil {
		log.Debug("Base32 Decode Err!")
		return dns.RcodeServerFailure, err

	}
	// log.Debug("Base32 Decode Err!")
	originDomain, err := Decrypt(vr.privateKey, ciphertxt, nil, nil)
	if err != nil {
		log.Error(err)
		return dns.RcodeServerFailure, err
	}

	ipkey := binary.BigEndian.Uint32(originDomain[len(originDomain)-4:])
	wr := NewResponseReverter(w, r, ipkey, start)
	if !utf8.Valid(originDomain[:len(originDomain)-4]) {
		log.Info("Invalid key!")
		return dns.RcodeRefused, nil
	}
	r.Question[0].Name = dns.Fqdn(string(originDomain[:len(originDomain)-4]))

	state := request.Request{W: w, Req: r}
	log.Info("Src ", state.IP(), " Decryption ", wr.originalQuestion.Name, " To ", r.Question[0].Name)
	RequestCount.Inc()
	go func() {
		type request struct {
			Time int64
			Src  string
			Dst  string
			Name string
		}
		b, err := json.Marshal(request{Time: start.UnixMicro(), Src: state.IP(), Dst: vr.local, Name: r.Question[0].Name})
		if err != nil {
			log.Error("JSON Marshal Error ", err)
			return
		}
		log.Debug("Json: ", b)
		vr.rdb.ZAdd(ctx1, "requests", redis.Z{
			Score:  float64(start.UnixMicro()),
			Member: b,
		})
		vr.rdb.ZIncrBy(ctx1, "fqdns", 1, r.Question[0].Name)
		mid, _ := strings.CutSuffix(r.Question[0].Name, ".")
		etld, err := publicsuffix.EffectiveTLDPlusOne(mid)
		if err != nil {
			log.Error("etld Error ", err)
			return
		}
		vr.rdb.ZIncrBy(ctx1, "slds", 1, etld)
	}()

	r.RecursionDesired = true
	rcode, err := plugin.NextOrFailure(vr.Name(), vr.Next, ctx, wr, r)

	if plugin.ClientWrite(rcode) {
		return rcode, err
	}
	// The next plugins didn't write a response, so write one now with the ResponseReverter.
	// If server.ServeDNS does this then it will create an answer mismatch.
	res := new(dns.Msg).SetRcode(r, rcode)
	state.SizeAndDo(res)
	wr.WriteMsg(res)
	// return success, so server does not write a second error response to client
	return dns.RcodeSuccess, err
}

// Name implements the Handler interface.
func (vr vpn_recv) Name() string { return name }
