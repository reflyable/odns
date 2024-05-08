// Package whoami implements a plugin that returns details about the resolving
// querying it.
package vpn_send

import (
	"context"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

const name = "vpn-root"

type vpn_root struct {
	Next      plugin.Handler
	node_list []string
	keyCache  []string
	c         *dns.Client
	forward   string
}

// ServeDNS implements the plugin.Handler interface.
func (vr vpn_root) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	// log.Debug(r.String())
	if r.Question[0].Qtype == dns.TypeTXT {
		res := new(dns.Msg).SetReply(r)
		rr := new(dns.TXT)
		rr.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}
		rr.Txt = vr.keyCache
		res.Answer = append(res.Answer, rr)
		w.WriteMsg(res)
		return dns.RcodeSuccess, nil
	}
	return plugin.NextOrFailure(vr.Name(), vr.Next, ctx, w, r)
}

func (vr *vpn_root) getKey(node string) (string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(node), dns.TypeTXT)
	in, _, err := vr.c.Exchange(m, vr.forward)
	if err != nil || len(in.Answer) == 0 {
		return "", err
	}
	if t, ok := in.Answer[0].(*dns.TXT); ok {
		for _, i := range t.Txt {
			return i, nil
		}
	}
	return "", dns.ErrKey

}

// Name implements the Handler interface.
func (vr vpn_root) Name() string { return name }
