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
const http = 3
const https = 4

func proxyResult(proxyType int, ok bool, key string) (rs []byte) {
	switch proxyType {
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
	case https:
		if ok {
			rs = []byte("HTTP/1.1 200 Connection established\n\n")
			log.Printf("[HTTPS] proxy client %s Success\n", key)
		} else {
			rs = []byte("HTTP/1.1 400\n\n")
			log.Printf("[HTTPS] proxy client %s Fail\n", key)
		}
	case http:
		rs = []byte("")
		if ok {

			log.Printf("[HTTP] proxy client %s Success\n", key)
		} else {
			log.Printf("[HTTP] proxy client %s Fail\n", key)
		}
	}
	return
}

func (s *server) setTarget(client net.Conn) (host string, port int, proxyType int, data []byte) {
	var (
		buffer [1024 * 4]byte
	)

	n, err := client.Read(buffer[:])
	if err != nil {
		log.Println(err)
		client.Close()
		return
	}

	switch buffer[0] {
	case 0x05:
		//response to client: no need to validation
		_, _ = client.Write([]byte{0x05, 0x00})
		n, err = client.Read(buffer[:])
		switch buffer[3] {
		case 0x01: //IP V4
			host = net.IPv4(buffer[4], buffer[5], buffer[6], buffer[7]).String()
		case 0x03: //domain name
			host = string(buffer[5 : 5+int(buffer[4])]) //b[4] length of domain name
		case 0x04: //IP V6
			host = net.IP{buffer[4], buffer[5], buffer[6], buffer[7], buffer[8], buffer[9], buffer[10], buffer[11], buffer[12], buffer[13], buffer[14], buffer[15], buffer[16], buffer[17], buffer[18], buffer[19]}.String()
		default:
			return
		}
		port = int(buffer[n-2])<<8 | int(buffer[n-1])
		proxyType = S5
	case 0x04:
		host = net.IPv4(buffer[4], buffer[5], buffer[6], buffer[7]).String()
		port = int(buffer[2])<<8 | int(buffer[3])
		proxyType = S4
	default:
		urlProtocol := strings.Split(string(buffer[:n]), " ")
		method := urlProtocol[0]
		if len(urlProtocol) >= 2 {
			if method == "CONNECT" {
				hostPort := strings.Split(urlProtocol[1], ":")
				if len(hostPort) == 2 {
					host = hostPort[0]
					port, err = strconv.Atoi(hostPort[1])
					if err == nil {
						proxyType = https
					}
				}
			} else {
				_url, err := url.Parse(urlProtocol[1])
				if err == nil {
					if strings.Index(_url.Host, ":") == -1 {
						host = _url.Host
						if _url.Scheme == "http" {
							port = 80
						} else {
							port = 443
						}
					} else {
						address := strings.Split(_url.Host, ":")
						host = address[0]
						port, err = strconv.Atoi(address[1])
					}
					if err == nil {
						proxyType = http
						data = buffer[:n]
					}
				}
			}
		}

	}
	return
}
