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
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"regexp"
	"strings"

	"golang.org/x/net/trace"
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
	instance = flag.String("instance", "default", "A name for this instance")
	gphtStr  = flag.String("graphite", "", "Graphite endpoint")
	monport  = flag.String("monport", "", "host:port to listen on for monitoring services")
)

func listenAndServe(addr string, config *tls.Config, rx *regexp.Regexp, method string) {
	lsnr, err := tls.Listen("tcp", *listen, config)
	if err != nil {
		log.Fatalf("Could not create listener, " + err.Error())
	}

	for {
		conn, err := lsnr.Accept()
		if err != nil {
			log.Printf("Could not accept connection, %v", err.Error())
		}

		tr := trace.NewEventLog("tlsprox."+*instance+".connection",
			fmt.Sprintf("%v <=> %v", conn.LocalAddr(), conn.RemoteAddr()))

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
				err := fmt.Sprintf("Connect from %v denied, no matching client certificates found", conn.RemoteAddr())
				log.Printf("%v", err)
				conn.Close()
				tr.Errorf(err)
				tr.Finish()
				continue
			}
		}

		log.Printf("Accepted connection from %v", conn.RemoteAddr())

		go handleConnection(method, addr, conn, tr)
	}
}

func handleConnection(method, addr string, c net.Conn, tr trace.EventLog) {
	defer tr.Finish()

	oc, err := net.Dial(method, addr)
	if err != nil {
		log.Printf("Could not connect to %v socket %v, %v", method, addr, err.Error())
		c.Close()
		return
	}

	cclose := make(chan struct{}, 1)
	sclose := make(chan struct{}, 1)
	var wait chan struct{}

	go copier(oc, c, cclose, tr)
	go copier(c, oc, sclose, tr)

	select {
	case <-cclose:
		oc.Close()
		wait = sclose
	case <-sclose:
		c.Close()
		wait = cclose
	}

	<-wait
}

func copier(dst, src net.Conn, srcClosed chan struct{}, tr trace.EventLog) {
	bs, err := io.Copy(dst, src)
	srcClosed <- struct{}{}

	// This is horrid (but good enough for Kube, basically, we're getting a
	// tlsconn in which doesn't support CloseRead, so we can't gently half close
	// these.
	if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
		log.Printf("Error on connection from %v to %v, %v", src.RemoteAddr(), dst.RemoteAddr(), err.Error())
		tr.Errorf("close with error, %s", err.Error())
	}

	log.Printf("Connection from %v to %v closed, transferred %v bytes", src.RemoteAddr(), dst.RemoteAddr(), bs)
	tr.Printf("closed")
}

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
		_, err = net.ResolveUnixAddr("unix", *sockPath)
		if err != nil {
			log.Fatalf("Could resolve socket name, " + err.Error())
		}
		method = "unix"
		addr = *sockPath
	}

	if *tcpEnd != "" {
		_, err = net.ResolveTCPAddr("tcp", *tcpEnd)
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

	if *monport != "" {
		go func() {
			log.Fatal(http.ListenAndServe(*monport, nil))
		}()
	}

	listenAndServe(addr, &config, rx, method)
}
