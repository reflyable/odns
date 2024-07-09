package vpn_recv

import (
	"encoding/pem"
	"os"
	"path/filepath"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/redis/go-redis/v9"
)

func init() {
	plugin.Register("vpn-recv", setup)
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		log.Error(err)
		return false
	}
	return !info.IsDir()
}

func ReadPrivatePem(path string) (privateKey *ecdsa.PrivateKey) {
	log.Info("prvKeyPem file ", path)
	if fileExists(path) {
		content, err := os.ReadFile(path)
		if err != nil {
			log.Fatal("prvKeyPem file read failed, error: ", err)
		}
		block, _ := pem.Decode(content)
		// 将pem格式私钥文件进行反序列化
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err == nil {
			return privateKey
		}
		log.Error(err)
	}
	log.Info("Generate Key")
	prv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal("Generate Key Failed, error: ", err)
	}
	privBytes, err := x509.MarshalECPrivateKey(prv)
	if err != nil {
		log.Fatal("Marshal ECPrivateKey Failed, error: ", err)
	}
	privPem := &pem.Block{
		Type:  "ecdsa private key",
		Bytes: privBytes,
	}

	// 写入文件
	pemFile, err := os.Create(path)
	if err != nil {
		log.Fatal("Create File ", path, " Failed, error: ", err)
	}
	defer pemFile.Close()
	err = pem.Encode(pemFile, privPem)
	if err != nil {
		log.Fatal("Write File ", path, " Failed, error: ", err)
	}
	return prv

}
func setup(c *caddy.Controller) error {
	c.Next()          // 'vpn-send'
	if !c.NextArg() { // Expect at least one value.
		return c.ArgErr() // Otherwise it's an error.
	}
	privateKey := c.Val()
	if !c.NextArg() { // Expect at least one value.
		println("here")
		return c.ArgErr() // Otherwise it's an error.
	}
	domain := c.Val()
	if !c.NextArg() { // Expect at least one value.
		println("here2")
		return c.ArgErr() // Otherwise it's an error.
	}
	redisString := c.Val()
	config := dnsserver.GetConfig(c)
	if !filepath.IsAbs(privateKey) && config.Root != "" {
		privateKey = filepath.Join(config.Root, privateKey)
	}
	opt, err := redis.ParseURL(redisString)
	if err != nil {
		println("here3 ", err)
		return c.ArgErr()
	}
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return vpn_recv{Next: next, privateKey: ReadPrivatePem(privateKey), domain: domain, rdb: redis.NewClient(opt), local: config.ListenHosts[0]}
	})

	return nil
}
