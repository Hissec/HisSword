package main

import (
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const FAIL = 0
const S5 = 1
const S4 = 2
const HTTP = 3

func proxyResult(proxytype int, ok bool, key string) (rs []byte) {
	switch proxytype {
	case S5:
		if ok {
			rs = []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
			log.Printf("[Sock5] proxy client %s Success\n", key)
		} else {
			rs = []byte{0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
			log.Printf("[Sock5] proxy client %s Fail\n", key)
		}
	case S4:
		if ok {
			rs = []byte{0x00, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
			log.Printf("[Sock4] proxy client %s Success\n", key)
		} else {
			rs = []byte{0x00, 0x5c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
			log.Printf("[Sock4] proxy client %s Fail\n", key)
		}
	case HTTP:
		if ok {
			rs = []byte("HTTP/1.1 200 Connection established\r\n\r\n")
			log.Printf("[HTTP] proxy client %s Success\n", key)
		} else {
			rs = []byte("HTTP/1.1 407 Unauthorized\r\n\r\n")
			log.Printf("[HTTP] proxy client %s Fail\n", key)
		}
	}
	return
}
func (s *server) setTarget(client net.Conn) (string, int, int) {
	var (
		b    [1024]byte
		host string
		port int
	)
	n, err := client.Read(b[:])
	if err != nil {
		log.Println(err)
		client.Close()
		return "", 0, FAIL
	}

	if b[0] == 0x05 { //only for socks5
		//response to client: no need to validation
		_, _ = client.Write([]byte{0x05, 0x00})
		n, err = client.Read(b[:])
		switch b[3] {
		case 0x01: //IP V4
			host = net.IPv4(b[4], b[5], b[6], b[7]).String()
		case 0x03: //domain name
			host = string(b[5 : 5+int(b[4])]) //b[4] length of domain name
		case 0x04: //IP V6
			host = net.IP{b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19]}.String()
		}
		port = int(b[n-2])<<8 | int(b[n-1])
		return host, port, S5
	} else if b[0] == 0x04 { //only for socks4
		host = net.IPv4(b[4], b[5], b[6], b[7]).String()
		port = int(b[2])<<8 | int(b[3])
		return host, port, S4
	} else { //http 代理https
		turl := strings.Split(string(b[:]), " ")
		if len(turl) < 3 {
			client.Close()
			return "", 0, FAIL
		}
		method := turl[0]
		if method == "CONNECT" {
			Url, err := url.Parse(turl[1])
			if err != nil {
				client.Close()
				return "", 0, FAIL
			}
			host = Url.Host
			port, err = strconv.Atoi(Url.Port())
			if err != nil {
				client.Close()
				return "", 0, FAIL
			}
			return host, port, HTTP
		} else {
			client.Close()
			return "", 0, FAIL
		}
	}
}
