package vpn_send

import (
	"io"
	"os"
	"strings"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/log"
	"github.com/miekg/dns"
)

func init() {
	plugin.Register("vpn-root", setup)
}

func ReadFile(path string) []string {
	fileHandle, err := os.OpenFile(path, os.O_RDONLY, 0666)
	if err != nil {
		return nil
	}

	defer fileHandle.Close()

	readBytes, err := io.ReadAll(fileHandle)
	if err != nil {
		return nil
	}

	results := strings.Split(string(readBytes), "\n")

	return results
}
func setup(c *caddy.Controller) error {
	c.Next()          // 'vpn-send'
	if !c.NextArg() { // Expect at least one value.
		return c.ArgErr() // Otherwise it's an error.
	}
	nodes_file := c.Val()
	node_list := ReadFile(nodes_file)
	log.Info("nodelist: ", node_list)
	if !c.NextArg() || node_list == nil { // Expect at least one value.
		return c.ArgErr() // Otherwise it's an error.
	}
	forward := c.Val()

	vr := vpn_root{Next: nil, node_list: node_list, keyCache: make([]string, len(node_list)), forward: forward, c: new(dns.Client)}
	for j, i := range node_list {
		_, ok := dns.IsDomainName(i)
		if !ok {
			continue
		}

		log.Info("getkeying ", i)

		res, err := vr.getKey(i)

		if err != nil || res == "" {
			log.Error(i, " getkey ", err)
		}
		log.Info(i, " ", res)
		vr.keyCache[j] = res

	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		vr.Next = next
		return vr
	})

	return nil
}
