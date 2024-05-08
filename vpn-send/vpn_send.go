// Package whoami implements a plugin that returns details about the resolving
// querying it.
package vpn_send

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/binary"
	math_rand "math/rand"
	"net"

	clog "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/coredns/coredns/plugin"
	"github.com/fatih/color"
	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("vpn_send")

const name = "vpn-send"

// Whoami is a plugin that returns your IP address, port and the protocol used for connecting
// to CoreDNS.
type vpn_send struct {
	Next      plugin.Handler
	domain    string
	pubCache  []node
	forwarder string
	c         *dns.Client
	ct        *dns.Client
	nsCache   map[string]net.IP
}

// ServeDNS implements the plugin.Handler interface.
func (vs *vpn_send) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	log.Debugf("%p %p\n", &vs.pubCache, &vs)
	if r.Question[0].Qtype != dns.TypeA {
		return plugin.NextOrFailure(vs.Name(), vs.Next, ctx, w, r)
	}
	in := vs.getReply(r)
	if in == nil {
		log.Error("nil")
		return dns.RcodeServerFailure, nil
	}
	log.Debug(len(vs.pubCache))
	w.WriteMsg(in)

	return dns.RcodeSuccess, nil
}

func (vs *vpn_send) getReply(r *dns.Msg) *dns.Msg {
	log.Debugf("%p %p\n", &vs.pubCache, &vs)
	originName := r.Question[0].Name
	ipkey := uint32(math_rand.Intn(len(vs.pubCache)))
	log.Debugf("\nSENDER IP MASK is %d : %b\n", ipkey, ipkey)
	log.Debug("SENDER encrypt query: ", originName)
	index := math_rand.Intn(len(vs.pubCache))
	domain, pub := vs.pubCache[index].domain, vs.pubCache[index].pub
	log.Debug(domain, " ", pub, " ", index, " ", originName)
	ciphertxt := binary.BigEndian.AppendUint32([]byte(originName), ipkey)
	ciphertxt, err := Encrypt(pub, ciphertxt, nil, nil)
	if err != nil {
		log.Error("encrypt")
		return nil
	}
	newQueryName := "0" + base32.StdEncoding.WithPadding('0').EncodeToString(ciphertxt)
	log.Debug("SENDER DNS Entry: ", newQueryName)
	var buffer bytes.Buffer
	i := 0
	for ; i < len(newQueryName)/63; i++ {
		buffer.WriteString(newQueryName[i*63 : i*63+63])
		buffer.WriteString(".")
	}
	if i*63 != len(newQueryName) {
		buffer.WriteString(newQueryName[i*63:])
		buffer.WriteString(".")
	}
	buffer.WriteString(domain)

	r.Question[0].Name = buffer.String()
	log.Debug(color.GreenString("SENDER DNS Send: " + r.Question[0].Name))
	in, _, err := vs.ct.Exchange(r, vs.forwarder)
	if err != nil {
		log.Error("exchange ", err)
		return nil
	}
	in.Question[0].Name = originName
	for _, rr := range in.Answer {
		if rr.Header().Rrtype == dns.TypeA {
			if rr.Header().Name == r.Question[0].Name {
				rr.Header().Name = originName
			}
			ip := make(net.IP, net.IPv4len)
			binary.BigEndian.PutUint32(ip, binary.BigEndian.Uint32(rr.(*dns.A).A.To4())^ipkey)
			rr.(*dns.A).A = ip
		}
	}
	r.Question[0].Name = originName
	return in
}

// Name implements the Handler interface.
func (vs vpn_send) Name() string { return name }
