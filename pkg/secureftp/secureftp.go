package secureftp

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
)

var (
	logger = log.New(os.Stdout, "", log.LstdFlags)
)

func getPasswordHandler(password string) func(ssh.Context, string) bool {
	return (func(ctx ssh.Context, user_password string) bool {
		return user_password == password
	})
}

func Run(user, password string, ip string, port int, ready chan struct{}) { //}, tempDir string) {
	server := ssh.Server{
		Addr:            fmt.Sprintf("%s:%d", ip, port), // IP and PORT to connect on
		PasswordHandler: ssh.PasswordHandler(getPasswordHandler(password)),
		SubsystemHandlers: map[string]ssh.SubsystemHandler{
			"sftp": func(sess ssh.Session) {
				logger.Printf("sFTP: Attempt")
				debugStream := os.Stdout
				serverOptions := []sftp.ServerOption{
					sftp.WithDebug(debugStream),
					//sftp.WithServerWorkingDirectory(tempDir),
				}
				server, err := sftp.NewServer(
					sess,
					serverOptions...,
				)
				if err != nil {
					logger.Printf("sFTP: Server init error: %s", err)
					return
				}
				if err := server.Serve(); err == io.EOF {
					server.Close()
					logger.Printf("sFTP: Client exited session.")
				} else if err != nil {
					logger.Printf("sFTP: Server completed with error: %s", err)
				}
			},
		},
	}
	logger.Printf("sFTP: Listening os %d", port)
	ready <- struct{}{}
	err := server.ListenAndServe()
	if err != nil {
		logger.Printf("sFTP: Failed to start the SSH server: %s", err)
	}
}

/*
func Run(user, password string, privateKey []byte, ip string, port int, ready chan struct{}, tempDir string) {
	log.Printf("sFTP: Run on %s:%d", ip, port)
	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Should use constant-time compare (or better, salt+hash) in
			// a production setting.
			log.Printf("sFTP: Login: %s", c.User())
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
	var listener net.Listener
	addr := fmt.Sprintf("%s:%d", ip, port)
	//for i := 0; ; i++ {
	//	if i == 10 {
	//		log.Fatalf("sFTP: failed to bind to %s", addr)
	//	}
	listener, err = net.Listen("tcp", addr)
	if err != nil {
		//log.Printf("sFTP: Failed to listen for connection: %v", err)
		log.Fatalf("sFTP: Failed to listen for connection: %v", err)
		//if bindError(err) {
		//		time.Sleep(500 * time.Millisecond)
		//		continue
		//}
	}
	//	break
	//	}
	log.Printf("sFTP: Listening on %s", listener.Addr())
	ready <- struct{}{}
	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Fatal("sFTP: Failed to accept incoming connection", err)
		}
		log.Print("sFTP: Accepted connection")
		// Before use, a handshake must be performed on the incoming
		// net.Conn.
		_, chans, reqs, err := ssh.NewServerConn(nConn, config)
		if err != nil {
			log.Fatal("sFTP: Failed to handshake", err)
		}
		log.Printf("sFTP: SSH server established")

		// The incoming Request channel must be serviced.
		go ssh.DiscardRequests(reqs)

		// Service the incoming Channel channel.
		for newChannel := range chans {
			// Channels have a type, depending on the application level
			// protocol intended. In the case of an SFTP session, this is "subsystem"
			// with a payload string of "<length=4>sftp"
			log.Printf("sFTP: Incoming channel: %s", newChannel.ChannelType())
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
			log.Printf("sFTP: Channel accepted")

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
			serverOptions := []sftp.ServerOption{
				sftp.WithDebug(os.Stdout),
				sftp.WithServerWorkingDirectory(tempDir),
			}
			server, err := sftp.NewServer(
				channel,
				serverOptions...,
			)
			if err != nil {
				log.Fatalf("sFTP: NewServer: %v", err)
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
*/
/*
func bindError(err error) bool {
	var e syscall.Errno
	if errors.As(err, &e) {
		return e == syscall.EACCES
	}
	return false
}
|*/
