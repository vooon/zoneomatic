package server

import "time"

type Cli struct {
	HTPasswdFile       string        `short:"p" long:"htpasswd" required:"" help:"Passwords file (bcrypt only)"`
	ZoneFiles          []string      `short:"z" long:"zone" required:"" help:"Zone files to update"`
	Listen             string        `long:"listen" default:"localhost:9999" help:"Server listen address"`
	AcceptProxy        bool          `long:"accept-proxy" help:"Accept PROXY protocol"`
	ProxyHeaderTimeout time.Duration `long:"proxy-header-timeout" default:"10s" help:"Timeout for PROXY headers"`
}

func Main() {

}
