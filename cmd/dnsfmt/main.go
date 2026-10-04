package main

import (
	"bytes"
	"io"
	"os"

	"github.com/alecthomas/kong"
	"github.com/vooon/zoneomatic/internal/buildinfo"
	"github.com/vooon/zoneomatic/pkg/dnsfmt"
	"github.com/vooon/zoneomatic/pkg/fileutil"
)

type Cli struct {
	Origin  string           `short:"o" name:"origin" help:"Zone origin; default: from $ORIGIN or the SOA owner name"`
	Inc     bool             `short:"i" name:"inc" default:"true" negatable:"" help:"Bump the SOA serial (default: ${default})"`
	Replace bool             `short:"r" name:"replace" help:"Rewrite the files in place instead of printing"`
	Files   []string         `arg:"" optional:"" placeholder:"FILE" type:"existingfile" help:"Zone files; stdin when none or '-'"`
	Version kong.VersionFlag `help:"Print version and exit"`
}

func main() {
	var cli Cli

	kctx := kong.Parse(&cli,
		kong.Description("Formats DNS zone files in the zoneomatic layout, keeping all comments."),
		kong.DefaultEnvars("DNSFMT"),
		kong.Vars{"version": buildinfo.String()},
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
