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
	log.Printf("sFTP: Run on %s:%d", ip, port)
	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Should use constant-time compare (or better, salt+hash) in
			// a production setting.
			log.Printf("sFTP: Login: %s\n", c.User())
			if c.User() == user && string(pass) == password {
				log.Printf("sFTP: User %s: access granted", c.User())
				return nil, nil
			}
			log.Printf("sFTP: User %s: access denied", c.User())
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}

	private, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		log.Fatal("sFTP: Failed to parse private key", err)
	}

	config.AddHostKey(private)
	for {
		// Once a ServerConfig has been configured, connections can be
		// accepted.
		listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ip, port))
		if err != nil {
			log.Fatal("sFTP: Failed to listen for connection", err)
		}
		log.Printf("sFTP: Listening on %v\n", listener.Addr())

		nConn, err := listener.Accept()
		if err != nil {
			log.Fatal("sFTP: Failed to accept incoming connection", err)
		}
		log.Printf("sFTP: Accepted connection: %v", nConn)
		// Before use, a handshake must be performed on the incoming
		// net.Conn.
		_, chans, reqs, err := ssh.NewServerConn(nConn, config)
		if err != nil {
			log.Fatal("sFTP: Failed to handshake", err)
		}
		log.Printf("sFTP: SSH server established\n")

		// The incoming Request channel must be serviced.
		go ssh.DiscardRequests(reqs)

		// Service the incoming Channel channel.
		for newChannel := range chans {
			// Channels have a type, depending on the application level
			// protocol intended. In the case of an SFTP session, this is "subsystem"
			// with a payload string of "<length=4>sftp"
			log.Printf("sFTP: Incoming channel: %s\n", newChannel.ChannelType())
			if newChannel.ChannelType() != "session" {
				err := newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
				if err != nil {
					log.Printf("sFTP: Reject channel: %v", err)
				}
				log.Printf("sFTP: Unknown channel type: %s", newChannel.ChannelType())
				continue
			}
			channel, requests, err := newChannel.Accept()
			if err != nil {
				log.Fatalf("sFTP: Could not accept channel: %v", err)
			}
			log.Printf("sFTP: Channel accepted\n")

			// Sessions have out-of-band requests such as "shell",
			// "pty-req" and "env".  Here we handle only the
			// "subsystem" request.
			go func(in <-chan *ssh.Request) {
				for req := range in {
					log.Printf("sFTP: Request: %v", req.Type)
					ok := false
					switch req.Type {
					case "subsystem":
						log.Printf("sFTP: Subsystem: %s", req.Payload[4:])
						if string(req.Payload[4:]) == "sftp" {
							ok = true
						}
					}
					log.Printf("sFTP: Accepted: %v", ok)
					if err := req.Reply(ok, nil); err != nil {
						log.Printf("sFTP: Reply: %v", err)
					}
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
				log.Print("sFTP: Client exited session.")
			} else if err != nil {
				log.Fatal("sFTP: server completed with error:", err)
			}
		}
		log.Print("sFTP: No more channels to process. Run once more")
	}
}
