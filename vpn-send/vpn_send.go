// Package whoami implements a plugin that returns details about the resolving
// querying it.
package vpn_send

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"

	// "fmt"
	"hash/crc32"
	math_rand "math/rand"
	"net"
	"strings"
	"time"

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
	prvCache  []node_prv
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
	index := math_rand.Intn(len(vs.pubCache))
	var in *dns.Msg
	var up int
	for {
		in, up = vs.getReply(r, index)
		if up == 0 {
			break
		}
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(vs.pubCache[index].domain), dns.TypeTXT)

		in, _, err := vs.c.Exchange(m, vs.forwarder)

		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		if in.Truncated {
			in, _, err = vs.ct.Exchange(m, vs.forwarder)
			if err != nil {
				time.Sleep(1 * time.Second)
				continue
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

				vs.pubCache[index] = node{R, i[44:]}
				break
			}
		}

	}
	if in == nil {
		log.Error("nil")
		return dns.RcodeServerFailure, nil
	}
	log.Debug(len(vs.pubCache))
	w.WriteMsg(in)

	return in.Rcode, nil
}

func (vs *vpn_send) getprv(index int) *ecdsa.PrivateKey {
	if time.Now().After(vs.prvCache[index].expire) {
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Warning("Prv key update failed")
		} else {
			vs.prvCache[index].prv = private
		}
		vs.prvCache[index].expire = time.Now().Add(1 * time.Hour)
	}
	return vs.prvCache[index].prv
}

// func printBytes(data []byte) {
// 	// 打印十六进制表示
// 	fmt.Println("Hexadecimal representation:")
// 	for _, b := range data {
// 		fmt.Printf("0x%02X ", b)
// 	}
// 	fmt.Println()

// 	// 打印ASCII可显示字符或十六进制
// 	fmt.Println("ASCII or Hexadecimal representation:")
// 	for _, b := range data {
// 		if b >= 32 && b <= 126 {
// 			fmt.Printf("%c ", b) // 打印可显示的ASCII字符
// 		} else {
// 			fmt.Printf("0x%02X ", b) // 打印不可显示字符的十六进制
// 		}
// 	}
// 	fmt.Println()
// }

func (vs *vpn_send) getReply(r *dns.Msg, index int) (*dns.Msg, int) {
	log.Debugf("%p %p\n", &vs.pubCache, &vs)
	originName := r.Question[0].Name
	buf := make([]byte, len(originName)+1)
	_, err := dns.PackDomainName(originName, buf, 0, nil, false)
	if err != nil {
		log.Error("pack ", err)
		return nil, 0
	}

	ipkey := math_rand.Uint32()
	// ipkey := uint32(303174162)
	log.Debugf("\nSENDER IP MASK is %d : %b\n", ipkey, ipkey)
	log.Debug("SENDER encrypt query: ", originName)

	domain, pub, prv := vs.pubCache[index].domain, vs.pubCache[index].pub, vs.getprv(index)
	log.Debug(domain, " ", pub, " ", index, " ", originName)
	buf = binary.BigEndian.AppendUint32(buf, ipkey)
	buf = binary.BigEndian.AppendUint32(buf, crc32.ChecksumIEEE(buf))
	buf, err = Encrypt(pub, prv, buf, nil, nil)
	if err != nil {
		log.Error("encrypt ", err)
		return nil, 0
	}
	newQueryName := "0" + base32.StdEncoding.WithPadding('1').EncodeToString(buf)
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

	// r.Question[0].Name = buffer.String()
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(buffer.String()), dns.TypeA)

	log.Debug(color.GreenString("SENDER DNS Send: " + buffer.String()))
	in, _, err := vs.c.Exchange(msg, vs.forwarder)
	if err != nil {
		log.Error("exchange ", err)
		return nil, 0
	}

	for _, rr := range in.Answer {
		if rr.Header().Rrtype == dns.TypeA {
			if rr.Header().Name == in.Question[0].Name {
				rr.Header().Name = originName
			}
			ip := make(net.IP, net.IPv4len)
			if ip.Equal(net.IP{255, 255, 255, 255}) {
				return nil, 1
			}
			binary.BigEndian.PutUint32(ip, binary.BigEndian.Uint32(rr.(*dns.A).A.To4())^ipkey)
			rr.(*dns.A).A = ip
		}
	}

	// r.Question[0].Name = originName
	in.Id = r.Id
	if in.Opcode == dns.OpcodeQuery {
		in.RecursionDesired = r.RecursionDesired // Copy rd bit
		in.CheckingDisabled = r.CheckingDisabled // Copy cd bit
	}

	if len(in.Question) > 0 {
		in.Question = []dns.Question{r.Question[0]}
	}
	if r.RecursionDesired {
		in.RecursionAvailable = true
	}
	log.Debug(in.String())
	return in, 0
}

// Name implements the Handler interface.
func (vs vpn_send) Name() string { return name }
