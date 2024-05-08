package vpn_send

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"net"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

type node struct {
	pub    *ecdsa.PublicKey
	domain string
}

func init() {
	plugin.Register("vpn-send", setup)
}

func getPubCache(c, ct *dns.Client, domain, forwarder string) []node {
	res := make([]node, 0, 10)
	for i := 3; i > 0; i-- {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)

		in, _, err := c.Exchange(m, forwarder)

		if err != nil {
			return nil
		}
		if in.Truncated {
			in, _, err = ct.Exchange(m, forwarder)
			if err != nil {
				return nil
			}
		}
		if len(in.Answer) == 0 {
			time.Sleep(1 * time.Second)
			continue
		}
		if t, ok := in.Answer[0].(*dns.TXT); ok {
			for _, i := range t.Txt {
				if len(i) < 44 {
					continue
				}
				cont, err := base64.StdEncoding.DecodeString(i[:44])
				if err != nil {
					return nil
				}
				R := new(ecdsa.PublicKey)
				R.Curve = elliptic.P256()
				R.X, R.Y = elliptic.UnmarshalCompressed(R.Curve, cont)
				if R.X == nil {
					log.Errorf("%s %v\n", "not valid key", cont)
				}
				res = append(res, node{R, i[44:]})

			}
		}
		return res
	}
	return nil
}

func setup(c *caddy.Controller) error {
	c.Next()          // 'vpn-send'
	if !c.NextArg() { // Expect at least one value.
		return c.ArgErr() // Otherwise it's an error.
	}

	domain := c.Val()
	if !c.NextArg() { // Expect at least one value.
		return c.ArgErr() // Otherwise it's an error.
	}

	forwarder := c.Val()
	// if !c.NextArg() { // Expect at least one value.
	// 	return c.ArgErr() // Otherwise it's an error.
	// }
	cu := new(dns.Client)
	ct := new(dns.Client)

	nscache := make(map[string]net.IP)
	ct.Net = "tcp"
	vs := &vpn_send{Next: nil, domain: domain, pubCache: nil, forwarder: forwarder, c: cu, ct: ct, nsCache: nscache}
	c.OnStartup(func() error {


		res := getPubCache(cu, ct, domain, forwarder)
		if res == nil {
			log.Error("getPubCache")
			return c.Err("getPubCache")
		}
		vs.pubCache = res
		log.Info("get PubCache: ", vs.pubCache)
		return nil
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		vs.Next = next
		return vs
	})

	return nil
}
