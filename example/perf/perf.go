package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"strconv"
	"math/big"
	"time"

	quic "github.com/lucas-clemente/quic-go"
)

var defaultChunkSize int

func main() {

	var chunksizeFlag = flag.Int("chunksize", 100000, "chunk size for sends")
	var downloadFlag = flag.Uint64("download", 0, "upload (size bytes)")
	var hostFlag = flag.String("host", "localhost", "hostname of server")
	var hpsFlag = flag.Bool("hps", false, "perform handshakes per second test")
	var portFlag = flag.String("port", "43333", "port")
	var parrallelFlag = flag.Int("parrallel", 1, "number of parrallel sessions to perform")
	var rpsFlag = flag.Bool("rps", false, "perform request per second test")
	var serverFlag = flag.Bool("server", false, "run as server")
	var throughputFlag = flag.Bool("throughput", false, "run throughput test")
	var uploadFlag = flag.Uint64("upload", 0, "upload (size bytes)")
	var uniFlag = flag.Bool("uni", false, "use unidirectional streams for throughput test")

	flag.Parse()

	addr := *hostFlag + ":" + *portFlag
	defaultChunkSize = *chunksizeFlag

	if *serverFlag {
		log.Println(perfServer(addr))
	} else {
		connections := *parrallelFlag
		if connections <= 0 {
			fmt.Println("Client: Nothing to do, parrallel connection <= 0, %v", connections)
		}
		if !(*throughputFlag || *rpsFlag || *hpsFlag) {
				fmt.Println("please specify at least one of -throughput, -rps or -hps")
				return
		}
		if *throughputFlag == true {
			if (*downloadFlag == 0) && (*uploadFlag == 0) {
				fmt.Println("Client: Nothing to do, upload and download transfer sizes are both 0")
				return
			}
			clientThroughputTest(addr, *uploadFlag, *downloadFlag, *uniFlag, strconv.Itoa(1))
		}
		if *rpsFlag == true {
			fmt.Println("this should perform the requests per second test (not yet implemented)", *parrallelFlag)
		}
		if *hpsFlag == true {
			fmt.Println("this should perform the handshakes per second test (not yet implemented)", *parrallelFlag)
		}
	}
}

// Start a quic perf server

func perfServer(addr string) error {
	listener, err := quic.ListenAddr(addr, generateTLSConfig(), nil)
	if err != nil {
		return err
	}
	for {
		sess, err := listener.Accept(context.Background())
		if err != nil {
			return err
		}
		go handleClientBi(sess)
		go handleClientUni(sess)
	}
}

// Handle perf client with accept for bidirecional stream
func handleClientBi(sess quic.Session) error {
	stream, err := sess.AcceptStream(context.Background())
	if err != nil {
		return err
	}

	buffer := make([]byte, 8)
	// Read length from client
	_, err = io.ReadAtLeast(stream, buffer, 8)

	if err != nil {
		stream.Close()
		return err
	}

	_, err = drainstream(stream, 0)
	transfersize := binary.BigEndian.Uint64(buffer)
	if err != nil {
		//TODO: Handle eof
		stream.Close()
		return err
	}

	if transfersize != 0 {
		fillstream(stream, transfersize)
		stream.Close()
	}
	return err
}

// Handle perf client with accept for bidirecional stream
func handleClientUni(session quic.Session) error {
	recvstream, err := session.AcceptUniStream(context.Background())
	if err != nil {
		return err
	}

	buffer := make([]byte, 8)
	// Read length from client
	_, err = io.ReadAtLeast(recvstream, buffer, 8)

	if err != nil {
		// TODO: actually handle errors
		panic(err)
	}

	_, err = drainstream(recvstream, 0)
	transfersize := binary.BigEndian.Uint64(buffer)
	if err != nil {
		//TODO: Handle
		panic(err)
	}

	sendstream, err := session.OpenUniStream()

	if err != nil {
		panic(err)
	}
	if transfersize != 0 {
		fillstream(sendstream, transfersize)
		sendstream.Close()
	}
	return err
}

func clientThroughputTest(addr string, upload, download uint64, uni bool, id string) error {

	testname := "client-" + id

	var start, end time.Time

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"perf"},
	}
	session, err := quic.DialAddr(addr, tlsConf, nil)
	if err != nil {
		return err
	}

	message := make([]byte, 8)
	binary.BigEndian.PutUint64(message, download)

	if uni {
		sendstream, err := session.OpenUniStreamSync(context.Background())
		if err != nil {
			return err
		}

		// first send server send size request
		start = time.Now()
		_, err = sendstream.Write(message)
		if err != nil {
			return err
		}

		if upload != 0 {
			bytesrecv, _ := fillstream(sendstream, upload)
			end = time.Now()
			fmt.Printf("%v: sent %v bytes in %v\n", testname, bytesrecv, end.Sub(start))
		}
		// Close the send stream to indicate to the server we are done
		sendstream.Close()

		if download != 0 {
			start = time.Now()
			recvstream, _ := session.AcceptUniStream(context.Background())
			bytesrecv, _ := drainstream(recvstream, download)
			end = time.Now()
			fmt.Printf("%v: received %v bytes in %v\n", testname, bytesrecv, end.Sub(start))
		}
	} else {
		stream, err := session.OpenStreamSync(context.Background())
		if err != nil {
			return err
		}

		// first send server send size request
		start = time.Now()
		_, err = stream.Write(message)
		if err != nil {
			return err
		}

		if upload != 0 {
			bytesrecv, _ := fillstream(stream, upload)
			end = time.Now()
			fmt.Printf("%v: sent %v bytes in %v\n", testname, bytesrecv, end.Sub(start))
		}
		// Close the send direction of this stream to indicate to the server we are done
		stream.Close()

		if download != 0 {
			start = time.Now()

			bytesrecv, _ := drainstream(stream, download)
			end = time.Now()
			fmt.Printf("%v: received %v bytes in %v\n", testname, bytesrecv, end.Sub(start))
		}
	}
	session.CloseWithError(0, "")
	return nil
}

func fillstream(stream quic.SendStream, transfersize uint64) (uint64, error) {
	var bytessent uint64
	chunksize := defaultChunkSize

	message := make([]byte, chunksize)

	for transfersize > 0 {
		// final chunk of data
		if transfersize < uint64(chunksize) {
			chunksize = int(transfersize)
			message = message[:chunksize]
		}
		transfersize -= uint64(chunksize)
		bytessent += uint64(chunksize)
		stream.Write(message)
	}
	return bytessent, nil
}

// transfer size of 0 is infinite
func drainstream(stream quic.ReceiveStream, transfersize uint64) (uint64, error) {
	var chunksize int = 1000
	var bytesrecv uint64 = 0
	buffer := make([]byte, chunksize)

	for {
		nbytes, err := io.ReadAtLeast(stream, buffer, chunksize)
		bytesrecv += uint64(nbytes)
		if err != nil {
			if errors.Is(err, io.EOF) {
				if (bytesrecv == transfersize) || (transfersize == 0) {
					return bytesrecv, nil
				} else {
					return bytesrecv, io.EOF
				}
			} else {
				panic(err)
			}
		}
	}
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"perf"},
	}
}
