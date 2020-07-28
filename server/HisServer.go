package main

import (
	"Hissec"
	"bytes"
	"crypto/aes"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

type server struct {
	tip        string
	tport      int
	lip        string
	lport      int
	cip        string
	cport      int
	pipe       net.Conn
	passwd     string
	content    chan []byte
	debug      bool
	clientpool sync.Map
	reverse    bool //管道链接方式 反向or正向
	entype     Hissec.Aes
	proxy      bool //服务类型，转发还是代理
}

const SIZE = 4
const KEYLENGTH = 32
const BUFSIZE = 1024 * 4

func (s *server) clearcontent() {
	//close(s.content)
	s.content = make(chan []byte, 1024)
	s.clientpool.Range(func(k, v interface{}) bool {
		v.(net.Conn).Close()
		s.clientpool.Delete(k)
		//log.Println("清理", k)
		return true
	})
}
func (s *server) waitpipe() {
	var buffer [1024]byte
	if s.reverse {
		//正向
		lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.cip, s.cport))
		if err != nil {
			log.Fatalln(err.Error())
		}
		lis = tls.NewListener(lis, Hissec.GetTls())
		log.Printf("Start pipe listened on %s\n", fmt.Sprintf("%s:%d", s.cip, s.cport))
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
					s.clearcontent()
					s.pipe = conn
					log.Printf("Establish pipe connect %s success\n", fmt.Sprintf("%s:%d", s.cip, s.cport))
				} else {
					_, _ = conn.Write([]byte("Fuck!"))
					conn.Close()
					log.Printf("Establish pipe connect %s faild: password error!\n", fmt.Sprintf("%s:%d", s.cip, s.cport))
				}
			} else {
				log.Println("UFO Connect...")
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
			conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", s.cip, s.cport), Hissec.GetTls())
			if err != nil {
				log.Printf("Establish pipe connect %s Failed. waiting retry...\n", fmt.Sprintf("%s:%d", s.cip, s.cport))
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
				s.clearcontent()
				s.pipe = conn
				log.Printf("Establish pipe connect %s success\n", conn.RemoteAddr())
			} else {
				_ = conn.Close()
				log.Printf("Establish pipe connect %s Fail:password error!  retry...\n", conn.RemoteAddr())
				time.Sleep(time.Second * 5)
			}
		}
	}
}
func (s *server) getket() string {
	key := Hissec.GetMd5Key()
	for {
		_, ok := s.clientpool.Load(key)
		if !ok {
			return key
		}
	}
}
func (s *server) closeClient(key string) {
	conn, ok := s.clientpool.Load(key)
	if !ok {
		//log.Println("Client not exist:", key)
		return
	}
	conn.(net.Conn).Close()
	s.clientpool.Delete(key)
	log.Printf("Close Client %s Success!\n", key)
}
func (s *server) closepipe() {
	if s.pipe != nil {
		s.pipe.Close()
		s.pipe = nil
	}
}
func (s *server) inContent(key string, tip string, tport int) {
	conn, ok := s.clientpool.Load(key)
	if !ok {
		log.Printf("Client %s not exist!\n", key)
		return
	}
	if s.proxy {
		s.content <- Hissec.BytesCombine([]byte(key), []byte(fmt.Sprintf("connect-start...%s:%d", tip, tport)))
	} else {
		s.content <- Hissec.BytesCombine([]byte(key), []byte(fmt.Sprintf("connect-start.%s:%d", s.tip, s.tport)))
	}

	var buffer [BUFSIZE - KEYLENGTH - aes.BlockSize]byte //AES加密最多会增加16字节
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
func (s *server) server() {
	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.lip, s.lport))
	if err != nil {
		log.Fatalln(err.Error())
	}
	log.Println("Start proxy server on", fmt.Sprintf("%s:%d", s.lip, s.lport))
	for {
		conn, err := lis.Accept()
		if err != nil {
			log.Println(err.Error())
		}
		log.Println("Recv new connect Client", conn.RemoteAddr())
		if s.proxy {
			host, port, proxytype := s.setTarget(conn)
			if host != "" && port != 0 && proxytype != 0 {
				key := fmt.Sprintf(`%s%d`, s.getket()[:KEYLENGTH-1], proxytype)
				s.clientpool.Store(key, conn)
				go s.inContent(key, host, port)
			}
			continue
		}
		key := s.getket()
		s.clientpool.Store(key, conn)
		go s.inContent(key, s.tip, s.tport)
	}
}
func (s *server) pipesend() {
	for {
		if s.pipe == nil {
			time.Sleep(time.Second * 3)
			continue
		}
		//content 32字节key+明文
		content, ok := <-s.content
		if !ok || s.pipe == nil {
			continue
		}
		if s.debug {
			text := content[KEYLENGTH:]
			log.Printf("%s send %d:\n%s\n", content[:KEYLENGTH], len(text), text)
		}

		_, err := s.pipe.Write(Hissec.Out(s.entype.Encode(content)))
		if err != nil {
			log.Println("Pipe error.wait...")
			s.closepipe()
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
			log.Println("Client had Interrupt closed.")
			continue
		}
		length, err := Hissec.BytesToInt(buffer[:SIZE])
		if length > BUFSIZE || length < KEYLENGTH || err != nil {
			log.Println("Read buffer length error.")
			//_, _ = s.pipe.Read(buffer[:]) //清除脏数据
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
			log.Println("pipe 解密失败！")
			continue
		}
		key := string(text[:KEYLENGTH])
		content := text[KEYLENGTH:]
		if s.debug {
			log.Printf("%s read %d:\n%s\n", key, len(content), content)
		}
		if bytes.Equal(content, []byte("connect-failed.")) {
			log.Printf("Client %s Closed.\n", key)
			if s.proxy {
				client, ok := s.clientpool.Load(key)
				if ok {
					proxytype, _ := strconv.Atoi(key[KEYLENGTH-1:])
					_, _ = client.(net.Conn).Write(proxyResult(proxytype, false, key))
				}
			}
			s.closeClient(key)
			continue
		}

		client, ok := s.clientpool.Load(key)
		if !ok {
			log.Printf("Client %s head Closed.\n", key)
		} else {
			//此信息只对代理模式打标，转发模式不处理。
			if bytes.Equal(content, []byte("connect-success.")) {
				if s.proxy {
					proxytype, _ := strconv.Atoi(key[KEYLENGTH-1:])
					content = proxyResult(proxytype, true, key)
				} else {
					continue
				}
			}
			_, err = client.(net.Conn).Write(content)
			if err != nil {
				s.content <- Hissec.BytesCombine([]byte(key), []byte("connect-failed."))
			}
		}
	}
}

func main() {
	lip := flag.String("a", "127.0.0.1", "Remote Forward Server IP")
	lport := flag.Int("p", 0, "Remote Forward Server Port")
	cip := flag.String("A", "", "Remote Forward target IP")
	cport := flag.Int("P", 0, "Remote Forward target Port")
	reverse := flag.Bool("reverse", false, "Pipe connect for reverse.")
	debug := flag.Bool("debug", false, "Show debug information.")
	passwd := flag.String("passwd", "Hissec!", "Pipe establish password.")
	tip := flag.String("tip", "", "Client connect target ip")
	tport := flag.Int("tport", 0, "Client connect target port")
	proxy := flag.Bool("proxy", false, "Server type Forward(default) or Proxy")
	flag.Parse()
	if *lport == 0 || *cip == "" || *cport == 0 || (!*proxy && (*tip == "" || *tport == 0)) {
		flag.Usage()
	} else {
		if *proxy {
			*tip = ""
			*tport = 0
		}
		s := server{lip: *lip, lport: *lport, cip: *cip, cport: *cport, reverse: *reverse, debug: *debug, content: make(chan []byte, 1024), passwd: *passwd, tip: *tip, tport: *tport, proxy: *proxy}
		go s.waitpipe()
		go s.pipesend()
		go s.piperead()
		s.server()
	}
}
