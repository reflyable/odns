package vpn_send

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"net"
	"strings"
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
type node_prv struct {
	prv    *ecdsa.PrivateKey
	expire time.Time
}

func init() {
	plugin.Register("vpn-send", setup)
}

func getPubCache(c, ct *dns.Client, domain, forwarder string) ([]node, []node_prv) {
	res := make([]node, 0, 10)
	res_prv := make([]node_prv, 0, 10)
	for i := 3; i > 0; i-- {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)

		in, _, err := c.Exchange(m, forwarder)

		if err != nil {
			return nil, nil
		}
		if in.Truncated {
			in, _, err = ct.Exchange(m, forwarder)
			if err != nil {
				return nil, nil
			}
		}
		if len(in.Answer) == 0 {
			time.Sleep(1 * time.Second)
			continue
		}
		if t, ok := in.Answer[0].(*dns.TXT); ok {
			for _, i := range t.Txt {
				ress := strings.SplitN(i, ".", 2)
				if len(ress) != 2 {
					continue
				}
				cont, err := base64.StdEncoding.DecodeString(ress[0])
				if err != nil {
					continue
				}
				var R *ecdsa.PublicKey
				tmp, err := x509.ParsePKIXPublicKey(cont)
				if err != nil {
					log.Errorf("%s %v\n", "not valid key", cont)
					continue
				}
				switch tmp := tmp.(type) {
				case *ecdsa.PublicKey:
					R = tmp

				default:
					continue
				}
				res = append(res, node{R, ress[1]})
				private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					continue
				}
				res_prv = append(res_prv, node_prv{private, time.Now().Add(1 * time.Hour)})
			}
		}
		return res, res_prv
	}
	return nil, nil
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
	cu.Timeout = 10 * time.Second
	ct := new(dns.Client)
	ct.Timeout = 10 * time.Second
	nscache := make(map[string]net.IP)
	ct.Net = "tcp"
	vs := &vpn_send{Next: nil, domain: domain, pubCache: nil, forwarder: forwarder, c: cu, ct: ct, nsCache: nscache}
	c.OnStartup(func() error {

		res, res_prv := getPubCache(cu, ct, domain, forwarder)
		if res == nil {
			log.Error("getPubCache")
			return c.Err("getPubCache")
		}
		vs.pubCache = res
		vs.prvCache = res_prv
		log.Info("get PubCache: ", vs.pubCache)
		return nil
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		vs.Next = next
		return vs
	})

	return nil
}
