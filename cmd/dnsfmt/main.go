package main

import (
	"flag"
	"io"
	"log"
	"os"

	"github.com/vooon/zoneomatic/pkg/dnsfmt"
)

var (
	flagOrigin = flag.String("o", "", "set the origin, otherwise taken from $ORIGIN or the owner name of the SOA record.")
	flagInc    = flag.Bool("i", true, "increase the serial")
)

func main() {
	flag.Parse()
	if flag.NArg() == 0 {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalf("dnsfmt: %s", err)
		}
		dnsfmt.Reformat(data, []byte(*flagOrigin), os.Stdout, *flagInc)
		return
	}

	for _, a := range flag.Args() {
		data, err := os.ReadFile(a)
		if err != nil {
			log.Fatalf("dnsfmt: %s", err)
		}
		dnsfmt.Reformat(data, []byte(*flagOrigin), os.Stdout, *flagInc)
	}
}
