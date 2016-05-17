package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
)

var (
	listen   = flag.String("listen", ":6658", "host:port to listen on")
	sockPath = flag.String("sock", "sock", "Path to unix socket to proxy to")
	certPath = flag.String("cert", "cert.pem", "Path to cert")
	keyPath  = flag.String("key", "key.pem", "Path to key")
	caPath   = flag.String("ca", "ca.pem", "Path to CA to auth clients against")
	noverify = flag.Bool("no-verify", false, "Disable verification, (voids the entire point of this, just for testing)")
)

func main() {
	flag.Parse()

	sock, err := net.ResolveUnixAddr("unix", *sockPath)
	if err != nil {
		log.Fatalf("Could not create listener, " + err.Error())
	}

	cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		log.Fatalf("Could not parse key/cert, " + err.Error())
	}

	cabs, err := ioutil.ReadFile(*caPath)
	if err != nil {
		log.Fatalf("Could not open ca file,, " + err.Error())
	}
	pool := x509.NewCertPool()
	ok := pool.AppendCertsFromPEM(cabs)
	if !ok {
		log.Fatalf("Failed loading ca certs")
	}

	config := tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	if !*noverify {
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = pool
	}

	config.Rand = rand.Reader

	lsnr, err := tls.Listen("tcp", *listen, &config)
	if err != nil {
		log.Fatalf("Could not create listener, " + err.Error())
	}

	for {
		conn, err := lsnr.Accept()
		if err != nil {
			log.Printf("Could not accept connection, %v", err.Error())
		}
		log.Printf("Accepted connection from %v", conn.RemoteAddr())
		go handleConnection(sock, conn)
	}
}

func handleConnection(addr *net.UnixAddr, c net.Conn) {
	oc, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		log.Printf("Could not connect to %v, %v", *addr, err.Error())
		c.Close()
		return
	}

	go func() {
		bs, err := io.Copy(c, oc)
		if err != nil {
			log.Printf("Error on connection from %v to %v, ", c.RemoteAddr(), oc.RemoteAddr(), err.Error())
		}

		log.Printf("Connection from %v to %v closed, transferred %v bytes", c.RemoteAddr(), oc.RemoteAddr(), bs)
	}()

	go func() {
		bs, err := io.Copy(oc, c)
		if err != nil {
			log.Printf("Error on connection from %v to %v, %v", oc.RemoteAddr(), c.RemoteAddr(), err.Error())
		}

		log.Printf("Connection from %v to %v closed, transferred %v bytes", oc.RemoteAddr(), c.RemoteAddr(), bs)
	}()
}
