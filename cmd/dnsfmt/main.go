package main

import (
	"bytes"
	"io"
	"os"

	"github.com/alecthomas/kong"
	"github.com/vooon/zoneomatic/pkg/dnsfmt"
	"github.com/vooon/zoneomatic/pkg/fileutil"
)

type Cli struct {
	Origin  string   `short:"o" name:"origin" help:"set the origin, otherwise taken from $ORIGIN or the owner name of the SOA record."`
	Inc     bool     `short:"i" name:"inc" default:"true" negatable:"" help:"increase the serial, default: ${default}"`
	Replace bool     `short:"r" name:"replace" help:"Replace file with formatted output"`
	Files   []string `arg:"" optional:"" placeholder:"FILE" type:"existingfile" help:"Zone file, use stdin if it is '-' or empty"`
}

func main() {
	var cli Cli

	kctx := kong.Parse(&cli,
		kong.Description("DNS Zone file formatter"),
		kong.DefaultEnvars("DNSFMT"),
	)

	if len(cli.Files) == 0 || (len(cli.Files) == 1 && cli.Files[0] == "-") {
		data, err := io.ReadAll(os.Stdin)
		kctx.FatalIfErrorf(err)

		err = dnsfmt.Reformat(data, []byte(cli.Origin), os.Stdout, cli.Inc)
		kctx.FatalIfErrorf(err)
		return
	}

	for _, a := range cli.Files {
		data, err := os.ReadFile(a)
		kctx.FatalIfErrorf(err)

		buf := bytes.NewBuffer(nil)

		err = dnsfmt.Reformat(data, []byte(cli.Origin), buf, cli.Inc)
		kctx.FatalIfErrorf(err)

		if cli.Replace {
			err = fileutil.AtomicWriteFile(a, buf.Bytes())
			kctx.FatalIfErrorf(err)
		} else {
			_, err = io.Copy(os.Stdout, buf)
			kctx.FatalIfErrorf(err)
		}
	}
}
