package main

import (
	"log"
	"net"
)

const FAIL = 0
const S5 = 1
const S4 = 2

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
	}
	return
}

func (s *server) setTarget(client net.Conn) (string, int, int) {
	var (
		buffer [1024]byte
		host   string
		port   int
	)
	n, err := client.Read(buffer[:])
	if err != nil {
		log.Println(err)
		client.Close()
		return "", 0, FAIL
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
			return "", 0, FAIL
		}
		port = int(buffer[n-2])<<8 | int(buffer[n-1])
		return host, port, S5
	case 0x04:
		host = net.IPv4(buffer[4], buffer[5], buffer[6], buffer[7]).String()
		port = int(buffer[2])<<8 | int(buffer[3])
		return host, port, S4
	default:
		return "", 0, FAIL
	}
}
