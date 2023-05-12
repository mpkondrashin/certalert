package secureftp

import (
	"fmt"
	"io"
	"log"
	"net"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func Run(user, password string, privateKey []byte, ip string, port int) {
	log.Printf("sFTP Run(%s, %s, %v, %s, %d)", user, password, privateKey, ip, port)
	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Should use constant-time compare (or better, salt+hash) in
			// a production setting.
			log.Printf("sFTP login: %s\n", c.User())
			if c.User() == user && string(pass) == password {
				log.Printf("sFTP user %s: access granted", c.User())
				return nil, nil
			}
			log.Printf("sFTP user %s: access denied", c.User())
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}

	private, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		log.Fatal("sFTP failed to parse private key", err)
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		log.Fatal("sFTP failed to listen for connection", err)
	}
	log.Printf("sFTP is listening on %v\n", listener.Addr())

	nConn, err := listener.Accept()
	if err != nil {
		log.Fatal("sFTP failed to accept incoming connection", err)
	}
	log.Printf("sFTP Accepted connection: %v", nConn)
	// Before use, a handshake must be performed on the incoming
	// net.Conn.
	_, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Fatal("sFTP failed to handshake", err)
	}
	log.Printf("sFTP SSH server established\n")

	// The incoming Request channel must be serviced.
	go ssh.DiscardRequests(reqs)

	// Service the incoming Channel channel.
	for newChannel := range chans {
		// Channels have a type, depending on the application level
		// protocol intended. In the case of an SFTP session, this is "subsystem"
		// with a payload string of "<length=4>sftp"
		log.Printf("Incoming channel: %s\n", newChannel.ChannelType())
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			log.Printf("Unknown channel type: %s\n", newChannel.ChannelType())
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Fatal("could not accept channel.", err)
		}
		log.Printf("Channel accepted\n")

		// Sessions have out-of-band requests such as "shell",
		// "pty-req" and "env".  Here we handle only the
		// "subsystem" request.
		go func(in <-chan *ssh.Request) {
			for req := range in {
				log.Printf("Request: %v\n", req.Type)
				ok := false
				switch req.Type {
				case "subsystem":
					log.Printf("Subsystem: %s\n", req.Payload[4:])
					if string(req.Payload[4:]) == "sftp" {
						ok = true
					}
				}
				log.Printf(" - accepted: %v\n", ok)
				req.Reply(ok, nil)
			}
		}(requests)

		serverOptions := []sftp.ServerOption{}
		//sftp.WithDebug(true),
		//}

		server, err := sftp.NewServer(
			channel,
			serverOptions...,
		)
		if err != nil {
			log.Fatal(err)
		}
		if err := server.Serve(); err == io.EOF {
			server.Close()
			log.Print("sftp client exited session.")
		} else if err != nil {
			log.Fatal("sftp server completed with error:", err)
		}
	}
}
