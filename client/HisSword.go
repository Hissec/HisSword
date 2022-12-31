package main

import (
	"Hissec"
	"Hissec/encryptPool"
	"Hissec/random"
	"bytes"
	"crypto/aes"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

type server struct {
	ip          string
	port        int
	pipe        net.Conn
	passwd      string
	content     chan []byte
	clientPool  sync.Map
	reverse     bool //管道链接方式 反向or正向
	encryptType encryptPool.Encrypt
	debug       bool
}

const SIZE = 4
const KEYLENGTH = 32
const BUFSIZE = 1024 * 4
const saltLength = 8
const certLength = 3072

func (s *server) logPrint(msg string) {
	if s.debug {
		log.Println(msg)
	}
}

func (s *server) clearContent() {
	for i := 0; i < len(s.content); i++ {
		<-s.content
	}
	s.clientPool.Range(func(k, v any) bool {
		v.(net.Conn).Close()
		s.clientPool.Delete(k)
		return true
	})
}
func (s *server) waitPipe() {
	if !s.reverse {
		//正向
		lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.ip, s.port))
		if err != nil {
			os.Exit(-1)
		}
		lis = tls.NewListener(lis, Hissec.GenerateCert(certLength))
		for {
			conn, err := lis.Accept()
			if err != nil {
				continue
			}
			if s.pipe == nil {
				if s.verify(conn) {
					s.pipe = conn
				} else {
					_, _ = conn.Write([]byte("Auth fail !"))
					conn.Close()
				}
			} else {
				_, _ = conn.Write([]byte("Fuck!"))
				conn.Close()
			}
		}
	} else {
		//反向
		for {
			if s.pipe != nil {
				time.Sleep(time.Second * 3)
				continue
			}
			conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", s.ip, s.port), Hissec.GenerateCert(certLength))
			if err != nil {
				time.Sleep(time.Second * 3)
				continue
			}
			if s.verify(conn) {
				s.pipe = conn
			} else {
				_ = conn.Close()
				time.Sleep(time.Second * 5)
			}
		}
	}
}

func (s *server) verify(conn net.Conn) bool {
	var buffer [1024]byte
	rs := false
	// 先写后读
	if s.reverse {
		saltString := random.RandString(saltLength)
		_, _ = conn.Write(Hissec.BytesCombine([]byte(saltString), []byte(Hissec.GetVerifyCode(saltString+s.passwd))))
		n, err := conn.Read(buffer[:])
		if err == nil {
			if n == saltLength+len(Hissec.GetVerifyCode("xxx")) {
				salt := buffer[:saltLength]
				value := buffer[saltLength:n]
				if bytes.Equal([]byte(Hissec.GetVerifyCode(string(salt)+s.passwd)), value) {
					rs = true
				}
			}
		}
	} else {
		// 先读后写
		n, err := conn.Read(buffer[:])
		if err == nil {
			if n == saltLength+len(Hissec.GetVerifyCode("xxx")) {
				salt := buffer[:saltLength]
				value := buffer[saltLength:n]
				if bytes.Equal([]byte(Hissec.GetVerifyCode(string(Hissec.BytesCombine(salt, []byte(s.passwd))))), value) {
					saltString := random.RandString(saltLength)
					_, err = conn.Write(Hissec.BytesCombine([]byte(saltString), []byte(Hissec.GetVerifyCode(saltString+s.passwd))))
					if err == nil {
						rs = true
					}
				}
			}
		}
	}
	return rs
}

func (s *server) closeClient(key string) {
	conn, ok := s.clientPool.Load(key)
	if !ok {
		return
	}
	conn.(net.Conn).Close()
	s.clientPool.Delete(key)
}
func (s *server) closePipe() {
	if s.pipe != nil {
		s.pipe.Close()
		s.pipe = nil
	}
	s.clearContent()
}

// 循环获取socket中的内容，放在消息管道中准备发给server
func (s *server) inContent(key string) {
	conn, ok := s.clientPool.Load(key)
	if !ok {
		s.content <- Hissec.BytesCombine([]byte(key), []byte("connect-failed.")) // 告诉对端socket不存在
		return
	}
	var buffer [BUFSIZE - KEYLENGTH - aes.BlockSize]byte
	for {
		n, err := conn.(net.Conn).Read(buffer[:])
		if err != nil {
			s.closeClient(key)
			s.content <- Hissec.BytesCombine([]byte(key), []byte("connect-failed."))
			break
		}
		s.content <- Hissec.BytesCombine([]byte(key), buffer[:n])
	}
}
func (s *server) client(key string, host string) {
	conn, err := net.Dial("tcp", host)
	if err != nil {
		s.logPrint(fmt.Sprintf("client connect: %s from %s fail", host, key))
		s.content <- Hissec.BytesCombine([]byte(key), []byte("connect-failed."))
	} else {
		s.logPrint(fmt.Sprintf("client connect: %s from %s success", host, key))
		// 客户端链接成功 存储到socket 池中
		s.clientPool.Store(key, conn)
		// 通知服务侧，该socket链接成功
		s.content <- Hissec.BytesCombine([]byte(key), []byte("connect-success."))
		s.inContent(key)
	}
}
func (s *server) pipeSend() {
	for {
		if s.pipe == nil {
			time.Sleep(time.Second * 3)
			continue
		}
		content := <-s.content
		if s.pipe != nil {
			_, err := s.pipe.Write(Hissec.Out(s.encryptType.Encode(content)))
			if err != nil {
				s.closePipe()
			}
		}
	}
}
func (s *server) pipeRead() {
	var buffer [BUFSIZE]byte
	for {
		if s.pipe == nil {
			time.Sleep(time.Second * 3)
			continue
		}
		n, err := s.pipe.Read(buffer[:SIZE])
		if err != nil {
			s.closePipe()
		}
		if n != SIZE {
			continue
		}
		length, err := Hissec.BytesToInt(buffer[:SIZE])
		if length > BUFSIZE || length < KEYLENGTH || err != nil {
			s.closePipe()
			continue
		}

		_, err = s.pipe.Read(buffer[:length])
		if err != nil {
			s.closePipe()
			continue
		}

		text, err := s.encryptType.Decode(buffer[:length])
		if err != nil {
			s.closePipe()
			continue
		}
		key := string(text[:KEYLENGTH])
		content := text[KEYLENGTH:]
		client, ok := s.clientPool.Load(key)
		if !ok {
			// 协议流:connect-start.IP:Port
			if bytes.HasPrefix(content, []byte("connect-start.")) {
				//链接目标IP:Port
				go s.client(key, string(content[len("connect-start."):]))
			}
			continue
		}
		// server侧该socket已关闭，现在关闭client侧socket
		if bytes.Equal(content, []byte("connect-failed.")) {
			s.logPrint(fmt.Sprintf("%s server侧该socket已关闭，现在关闭client侧sockets", key))
			s.closeClient(key)
			continue
		}

		// 循环读取管道中消息，发送给对应的socket
		_, err = client.(net.Conn).Write(content)
		if err != nil {
			s.closeClient(key)
			s.content <- Hissec.BytesCombine([]byte(key), []byte("connect-failed."))
		}
	}
}

func main() {
	ip := flag.String("a", "", "PIPE IP")
	port := flag.Int("p", 0, "PIPE Port")
	reverse := flag.Bool("r", false, "Pipe connect for reverse.")
	debug := flag.Bool("debug", false, "debug log.")
	passwd := flag.String("passwd", "Hissec!", "Pipe establish password.")
	enCrypt := flag.String("enCrypt", "empty", fmt.Sprintf("enCrypt type for pipe connect\n\tOnly sypport %v", encryptPool.GetEncryptList()))
	flag.Parse()
	enCryptInstance, err := encryptPool.GetEncrypt(*enCrypt)
	if err != nil {
		fmt.Printf("enCrypt type %s is not support!!\n\t Now Only Support %v", *enCrypt, encryptPool.GetEncryptList())
	} else {
		if *ip == "" || *port == 0 {
			flag.Usage()
		} else {
			s := server{ip: *ip, port: *port, reverse: *reverse, passwd: *passwd,
				content: make(chan []byte, 1024), debug: *debug, encryptType: enCryptInstance}
			go s.waitPipe()
			go s.pipeSend()
			s.pipeRead()
		}
	}
}
