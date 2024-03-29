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
	"strconv"
	"sync"
	"time"
)

type server struct {
	tip        string
	tPort      int
	lip        string
	lPort      int
	cip        string
	cPort      int
	pipe       net.Conn
	passwd     string
	content    chan []byte
	debug      bool
	clientPool sync.Map
	reverse    bool //管道链接方式 反向or正向
	enCrypt    encryptPool.Encrypt
	proxy      bool //服务类型，转发还是代理
}

type connTarget struct {
	conn     net.Conn
	ip       string
	port     int
	connType string
	data     []byte
}

const size = 4
const keyLength = 32
const buffSize = 1024 * 4
const saltLength = 8
const certLength = 3072

func (s *server) clearContent() {
	for i := 0; i < len(s.content); i++ {
		<-s.content
	}
	s.clientPool.Range(func(k, v any) bool {
		v.(connTarget).conn.Close()
		s.clientPool.Delete(k)
		return true
	})
}

func (s *server) waitPipe() {
	if s.reverse {
		//正向
		lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.cip, s.cPort))
		if err != nil {
			log.Fatalln(err.Error())
		}
		lis = tls.NewListener(lis, Hissec.GenerateCert(certLength))
		log.Printf("Start pipe listened on %s\n", fmt.Sprintf("%s:%d", s.cip, s.cPort))
		for {
			conn, err := lis.Accept()
			if err != nil {
				continue
			}
			if s.pipe == nil {
				if s.verify(conn) {
					s.pipe = conn
					log.Printf("Establish pipe connect %s success\n", fmt.Sprintf("%s:%d", s.cip, s.cPort))
				} else {
					_, _ = conn.Write([]byte("Fuck!"))
					conn.Close()
					log.Printf("Establish pipe connect %s faild: password error!\n", fmt.Sprintf("%s:%d", s.cip, s.cPort))
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
			conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", s.cip, s.cPort), Hissec.GenerateCert(certLength))
			if err != nil {
				log.Printf("Establish pipe connect %s Failed. waiting retry...\n", fmt.Sprintf("%s:%d", s.cip, s.cPort))
				time.Sleep(time.Second * 3)
				continue
			}
			if s.verify(conn) {
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

func (s *server) verify(conn net.Conn) bool {
	var buffer [1024]byte
	rs := false
	// 连接先写后读
	if !s.reverse {
		saltString := random.RandString(saltLength)
		_, _ = conn.Write(Hissec.BytesCombine([]byte(saltString), []byte(Hissec.GetVerifyCode(saltString+s.passwd))))
		n, err := conn.Read(buffer[:])
		if err == nil {
			if n == saltLength+len(Hissec.GetVerifyCode("xxx")) {
				salt := buffer[:saltLength]
				value := buffer[saltLength:n]
				if bytes.Equal([]byte(Hissec.GetVerifyCode(string(Hissec.BytesCombine(salt, []byte(s.passwd))))), value) {
					rs = true
				}
			}
		}
	} else {
		// 监听先读后写
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

func (s *server) getKet() string {
	key := Hissec.GetMd5Key()
	for {
		_, ok := s.clientPool.Load(key)
		if !ok {
			return key
		}
	}
}
func (s *server) closeClient(key string) {
	connTag, ok := s.clientPool.Load(key)
	if !ok {
		return
	}
	connTag.(connTarget).conn.Close()
	log.Printf("Close Client %s %s Success!\n", key, func() string {
		connTag, ok := s.clientPool.Load(key)
		if ok {
			connTa := connTag.(connTarget)
			return fmt.Sprintf("[%s:%d] [%s]", connTa.ip, connTa.port, connTa.connType)
		}
		return "closed"
	}())
	s.clientPool.Delete(key)
	log.Printf("socket pool size: %d\n", func() int {
		sum := 0
		s.clientPool.Range(func(key, value any) bool {
			sum += 1
			return true
		})
		return sum
	}())
}
func (s *server) closePipe() {
	if s.pipe != nil {
		s.pipe.Close()
		s.pipe = nil
	}
	s.clearContent()
}
func (s *server) inContent(key string, tip string, tport int) {
	connTag, ok := s.clientPool.Load(key)
	if !ok {
		log.Printf("Client %s not exist!\n", key)
		return
	}
	s.content <- Hissec.BytesCombine([]byte(key), []byte(fmt.Sprintf("connect-start.%s:%d", tip, tport)))

	var buffer [buffSize - keyLength - aes.BlockSize]byte //AES加密最多会增加16字节
	for {
		n, err := connTag.(connTarget).conn.Read(buffer[:])
		if err != nil {
			s.closeClient(key)
			s.content <- Hissec.BytesCombine([]byte(key), []byte("connect-failed."))
			break
		}
		s.content <- Hissec.BytesCombine([]byte(key), buffer[:n])
	}
}
func (s *server) server() {
	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.lip, s.lPort))
	if err != nil {
		log.Fatalln(err.Error())
	}
	log.Println("Start proxy server on", fmt.Sprintf("%s:%d", s.lip, s.lPort))
	for {
		conn, err := lis.Accept()
		if err != nil {
			log.Println(err.Error())
		}
		log.Println("Recv new connect Client", conn.RemoteAddr())
		if s.proxy {
			host, port, prototype, data := s.setTarget(conn)
			if host != "" && port != 0 && prototype != 0 {
				key := fmt.Sprintf(`%s%d`, s.getKet()[:keyLength-1], prototype)
				pType := func() string {
					switch prototype {
					case S5:
						return "Socket5"
					case S4:
						return "Socket4"
					case https:
						return "HTTPS"
					case http:
						return "HTTP"
					default:
						return "Direct"
					}
				}()
				s.clientPool.Store(key, connTarget{conn: conn, ip: host, port: port, connType: pType, data: data})
				log.Printf("New client %s [%s:%d] [%s] Success!\n", key, host, port, pType)
				go s.inContent(key, host, port)
			}
			continue
		} else {
			key := s.getKet()
			s.clientPool.Store(key, connTarget{conn: conn, ip: s.tip, port: s.tPort, connType: "Direct"})
			log.Printf("New client %s [%s:%d] [%s] Success!\n", key, s.tip, s.tPort, "Direct")
			go s.inContent(key, s.tip, s.tPort)
		}

	}
}
func (s *server) pipeSend() {
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
			text := content[keyLength:]
			connTag, ok := s.clientPool.Load(string(content[:keyLength]))
			if ok {
				connTa := connTag.(connTarget)
				log.Printf("%s-%s send %d:\n%s\n", content[:keyLength],
					fmt.Sprintf("%s:%d:%s", connTa.ip, connTa.port, connTa.connType), len(text), text)
			}

		}

		_, err := s.pipe.Write(Hissec.Out(s.enCrypt.Encode(content)))
		if err != nil {
			log.Println("Pipe error.wait...")
			s.closePipe()
		}
	}
}
func (s *server) pipeRead() {
	var buffer [buffSize]byte
	for {
		if s.pipe == nil {
			time.Sleep(time.Second * 3)
			continue
		}
		n, err := s.pipe.Read(buffer[:size])
		if err != nil {
			s.closePipe()
		}
		if n != size {
			log.Println("Client had Interrupt closed.")
			continue
		}
		length, err := Hissec.BytesToInt(buffer[:size])
		if length > buffSize || length < keyLength || err != nil {
			log.Println("Read buffer length error.")
			continue
		}

		_, err = s.pipe.Read(buffer[:length])
		if err != nil {
			s.closePipe()
			continue
		}

		text, err := s.enCrypt.Decode(buffer[:length])
		if err != nil {
			log.Println("pipe 解密失败！")
			continue
		}
		key := string(text[:keyLength])
		content := text[keyLength:]
		if s.debug {
			connTag, ok := s.clientPool.Load(key)
			if ok {
				connTa := connTag.(connTarget)
				log.Printf("%s-%s read %d:\n%s\n", key, fmt.Sprintf("%s:%d:%s", connTa.ip, connTa.port, connTa.connType), len(content), content)
			}

		}
		if bytes.Equal(content, []byte("connect-failed.")) {
			if s.proxy {
				connTag, ok := s.clientPool.Load(key)
				if ok {
					proxytype, _ := strconv.Atoi(key[keyLength-1:])
					_, _ = connTag.(connTarget).conn.Write(proxyResult(proxytype, false, key))
				}
			}
			s.closeClient(key)
			continue
		}

		connTag, ok := s.clientPool.Load(key)
		if !ok {
			log.Printf("Client %s had Closed.\n", key)
			s.content <- Hissec.BytesCombine([]byte(key), []byte("connect-failed."))

		} else {
			//此信息只对代理模式打标，转发模式不处理。
			if bytes.Equal(content, []byte("connect-success.")) {
				if s.proxy {
					prototype, _ := strconv.Atoi(key[keyLength-1:])
					// http 不需给client回复hello包
					if prototype == http {
						s.content <- Hissec.BytesCombine([]byte(key), connTag.(connTarget).data)
						continue
					}
					content = proxyResult(prototype, true, key)
				} else {
					continue
				}
			} else {
				if bytes.Equal(content, []byte("connect-failed.")) {
					prototype, _ := strconv.Atoi(key[keyLength-1:])
					content = proxyResult(prototype, false, key)
					_, err = connTag.(connTarget).conn.Write(content)
					s.closeClient(key)
					continue
				}
			}
			_, err = connTag.(connTarget).conn.Write(content)
			if err != nil {
				s.content <- Hissec.BytesCombine([]byte(key), []byte("connect-failed."))
				s.clientPool.Delete(key)
			}
		}

	}
}

func main() {
	lip := flag.String("a", "127.0.0.1", "Remote Forward Server IP")
	listenPort := flag.Int("p", 1080, "Remote Forward Server Port")
	cip := flag.String("A", "", "Remote Forward target IP")
	pipePort := flag.Int("P", 0, "Remote Forward target Port")
	reverse := flag.Bool("r", false, "Pipe connect for reverse.")
	debug := flag.Bool("d", false, "Show debug information.")
	passwd := flag.String("passwd", "Hissec!", "Pipe establish password.")
	tip := flag.String("tip", "", "Client connect target ip")
	tport := flag.Int("tPort", 0, "Client connect target port")
	proxy := flag.Bool("proxy", false, "Server type Forward(default) or Proxy")
	enCrypt := flag.String("enCrypt", "empty", fmt.Sprintf("enCrypt type for pipe connect\n\tOnly sypport %v", encryptPool.GetEncryptList()))
	flag.Parse()
	enCryptInstance, err := encryptPool.GetEncrypt(*enCrypt)
	if err != nil {
		fmt.Printf("enCrypt type %s is not support!!\n\tNow Only Support %v", *enCrypt, encryptPool.GetEncryptList())
	} else {
		if *cip == "" || *pipePort == 0 || (!*proxy && (*tip == "" || *tport == 0)) {
			flag.Usage()
		} else {
			if *proxy {
				*tip = ""
				*tport = 0
			}
			s := server{lip: *lip, lPort: *listenPort, cip: *cip, cPort: *pipePort,
				reverse: *reverse, debug: *debug, content: make(chan []byte, 1024),
				passwd: *passwd, tip: *tip, tPort: *tport, proxy: *proxy, enCrypt: enCryptInstance}
			go s.waitPipe()
			go s.pipeSend()
			go s.pipeRead()
			s.server()
		}
	}

}
