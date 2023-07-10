package secureftp

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
)

/*
var (

	logger = log.New(os.Stdout, "", log.LstdFlags)

)
*/
func getPasswordHandler(password string) func(ssh.Context, string) bool {
	return (func(ctx ssh.Context, user_password string) bool {
		return user_password == password
	})
}

func Run(user, password string, ip string, port int) {
	server := ssh.Server{
		Addr:            fmt.Sprintf("%s:%d", ip, port),
		PasswordHandler: ssh.PasswordHandler(getPasswordHandler(password)),
		SubsystemHandlers: map[string]ssh.SubsystemHandler{
			"sftp": func(sess ssh.Session) {
				log.Printf("sFTP: Attempt")
				debugStream := os.Stdout
				serverOptions := []sftp.ServerOption{
					sftp.WithDebug(debugStream),
				}
				server, err := sftp.NewServer(
					sess,
					serverOptions...,
				)
				if err != nil {
					log.Printf("sFTP: Server init error: %s", err)
					return
				}
				if err := server.Serve(); err == io.EOF {
					server.Close()
					log.Printf("sFTP: Client exited session.")
				} else if err != nil {
					log.Printf("sFTP: Server completed with error: %s", err)
				}
			},
		},
	}
	log.Printf("sFTP: Listening on %d", port)
	err := server.ListenAndServe()
	if err != nil {
		log.Printf("sFTP: Failed to start the SSH server: %s", err)
	}
}
