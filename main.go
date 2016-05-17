// Copyright 2016 Qubit Digital Ltd  All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	"regexp"
)

var (
	listen   = flag.String("listen", ":6658", "host:port to listen on")
	sockPath = flag.String("sock", "", "Path to unix socket to proxy to")
	tcpEnd   = flag.String("tcp", "", "TCP remote end point to connect to")
	certPath = flag.String("cert", "cert.pem", "Path to cert")
	keyPath  = flag.String("key", "key.pem", "Path to key")
	caPath   = flag.String("ca", "ca.pem", "Path to CA to auth clients against")
	noverify = flag.Bool("no-verify", false, "Disable verification, (voids the entire point of this, just for testing)")
	regexStr = flag.String("regex", ".*", "Regular expression to match against CNs (start and end anchors will be added)")
)

func main() {
	flag.Parse()

	if *tcpEnd == "" && *sockPath == "" {
		log.Fatalf("You must specify a tcp or socket to pass traffic to\n")
	}

	if *tcpEnd != "" && *sockPath != "" {
		log.Fatalf("Can only specify one tcp or unix socket to pass traffic to\n")
	}

	rx, err := regexp.Compile("^" + *regexStr + "$")
	if err != nil {
		log.Fatalf("Can only specify one tcp or unix socket to pass traffic to\n")
	}

	method := ""
	addr := ""
	if *sockPath != "" {
		_, err := net.ResolveUnixAddr("unix", *sockPath)
		if err != nil {
			log.Fatalf("Could resolve socket name, " + err.Error())
		}
		method = "unix"
		addr = *sockPath
	}

	if *tcpEnd != "" {
		_, err := net.ResolveTCPAddr("tcp", *tcpEnd)
		if err != nil {
			log.Fatalf("Could resolve TCP address, " + err.Error())
		}
		method = "tcp"
		addr = *tcpEnd
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
		RootCAs:      pool,
	}
	config.BuildNameToCertificate()

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

		tlsconn, ok := conn.(*tls.Conn)
		if !ok {
			log.Printf("Failed to cast net.Conn from tls.Conn, no idea how that can happen!\n")
		}

		// We want to specifically match hostnames, so we'll manually trigger the
		// handshake here so that ConnectionState is populated when we attempt
		// verification
		tlsconn.Handshake()

		if !*noverify {
			verified := false
			for _, p := range tlsconn.ConnectionState().PeerCertificates {
				if rx.Match([]byte(p.Subject.CommonName)) {
					verified = true
					break
				}
			}
			if !verified {
				log.Printf("Connect from %v denied, no matching client certificates found", conn.RemoteAddr())
				conn.Close()
				continue
			}
		}

		log.Printf("Accepted connection from %v", conn.RemoteAddr())
		go handleConnection(method, addr, conn)
	}
}

func handleConnection(method, addr string, c net.Conn) {
	oc, err := net.Dial(method, addr)
	if err != nil {
		log.Printf("Could not connect to %v socket %v, %v", method, addr, err.Error())
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
