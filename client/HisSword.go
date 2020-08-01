package main

import (
	"Hissec"
	"bytes"
	"crypto/aes"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

type server struct {
	ip         string
	port       int
	pipe       net.Conn
	passwd     string
	content    chan []byte
	clientpool sync.Map
	reverse    bool //管道链接方式 反向or正向
	entype     Hissec.Aes
}

const SIZE = 4
const KEYLENGTH = 32
const BUFSIZE = 1024 * 4

func (s *server) clearcontent() {
	for i := 0; i < len(s.content); i++ {
		<-s.content
	}
	s.clientpool.Range(func(k, v interface{}) bool {
		v.(net.Conn).Close()
		s.clientpool.Delete(k)
		return true
	})
}
func (s *server) waitpipe() {
	var buffer [1024]byte
	if !s.reverse {
		//正向
		lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.ip, s.port))
		if err != nil {
			os.Exit(-1)
		}
		lis = tls.NewListener(lis, Hissec.GetTls())
		for {
			conn, err := lis.Accept()
			if err != nil {
				continue
			}
			if s.pipe == nil {
				n, err := conn.Read(buffer[:])
				if err != nil {
					conn.Close()
					continue
				}
				if bytes.Equal(buffer[:n], []byte(s.passwd)) {
					_, err = conn.Write(buffer[:n])
					if err != nil {
						conn.Close()
						continue
					}
					s.pipe = conn
				} else {
					_, _ = conn.Write([]byte("Fuck!"))
					conn.Close()
				}
			} else {
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
			conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", s.ip, s.port), Hissec.GetTls())
			if err != nil {
				time.Sleep(time.Second * 3)
				continue
			}
			_, _ = conn.Write([]byte(s.passwd))
			n, err := conn.Read(buffer[:])
			if err != nil {
				_ = conn.Close()
				time.Sleep(time.Second * 3)
				continue
			}
			if bytes.Equal(buffer[:n], []byte(s.passwd)) {
				s.pipe = conn
			} else {
				_ = conn.Close()
				time.Sleep(time.Second * 5)
			}
		}
	}
}
func (s *server) closeClient(key string) {
	conn, ok := s.clientpool.Load(key)
	if !ok {
		return
	}
	conn.(net.Conn).Close()
	s.clientpool.Delete(key)
}
func (s *server) closepipe() {
	if s.pipe != nil {
		s.pipe.Close()
		s.pipe = nil
	}
	s.clearcontent()
}
func (s *server) inContent(key string) {
	conn, ok := s.clientpool.Load(key)
	if !ok {
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
func (s *server) client(key string, host string, forward bool) {
	conn, err := net.Dial("tcp", host)
	if err != nil {
		s.content <- Hissec.BytesCombine([]byte(key), []byte("connect-failed."))
	} else {
		s.clientpool.Store(key, conn)
		//为了给服务端代理模式打标
		s.content <- Hissec.BytesCombine([]byte(key), []byte("connect-success."))
		if forward {
			go s.inContent(key)
		} else {
			s.inContent(key)
		}

	}
}
func (s *server) pipesend() {
	for {
		if s.pipe == nil {
			time.Sleep(time.Second * 3)
			continue
		}
		content := <-s.content
		if s.pipe != nil {
			_, err := s.pipe.Write(Hissec.Out(s.entype.Encode(content)))
			if err != nil {
				s.closepipe()
			}
		}
	}
}
func (s *server) piperead() {
	var buffer [BUFSIZE]byte
	for {
		if s.pipe == nil {
			time.Sleep(time.Second * 3)
			continue
		}
		n, err := s.pipe.Read(buffer[:SIZE])
		if err != nil {
			s.closepipe()
		}
		if n != SIZE {
			continue
		}
		length, err := Hissec.BytesToInt(buffer[:SIZE])
		if length > BUFSIZE || length < KEYLENGTH || err != nil {
			continue
		}

		//if s.pipe == nil {
		//	continue
		//}
		_, err = s.pipe.Read(buffer[:length])
		if err != nil {
			s.closepipe()
			continue
		}

		text, err := s.entype.Decode(buffer[:length])
		if err != nil {
			continue
		}
		key := string(text[:KEYLENGTH])
		content := text[KEYLENGTH:]
		client, ok := s.clientpool.Load(key)
		if !ok {
			if bytes.HasPrefix(content, []byte("connect-start.")) {
				//链接目标IP:Port
				if string(content[len("connect-start."):len("connect-start.")+2]) == ".." {
					go s.client(key, string(content[len("connect-start..."):]), false)
				} else {
					s.client(key, string(content[len("connect-start."):]), true)
				}
			} else {
				s.content <- Hissec.BytesCombine([]byte(key), []byte("connect-failed."))
			}
			continue
		}
		if bytes.Equal(content, []byte("connect-failed.")) {
			s.closeClient(key)
			continue
		}
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
	reverse := flag.Bool("reverse", false, "Pipe connect for reverse.")
	passwd := flag.String("passwd", "Hissec!", "Pipe establish password.")
	flag.Parse()
	if *ip == "" || *port == 0 {
		flag.Usage()
	} else {
		s := server{ip: *ip, port: *port, reverse: *reverse, passwd: *passwd, content: make(chan []byte, 1024)}
		go s.waitpipe()
		go s.pipesend()
		s.piperead()
	}
}
