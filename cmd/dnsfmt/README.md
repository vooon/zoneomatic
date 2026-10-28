# dnsfmt

Formats DNS zone files in the layout zoneomatic writes, keeping every comment
and `$`-directive. It is a thin command line over the
[go-masterfile](https://github.com/vooon/go-masterfile) library, which
zoneomatic itself uses to rewrite zones: a file formatted with `dnsfmt` is not
touched again by a zoneomatic update of the same version.

```
dnsfmt [--no-inc] [-o ORIGIN] [-r] [FILE]...
```

Without files (or with `-`) it reads standard input and prints the result;
with `-r` it rewrites the files in place. The SOA serial is bumped unless
`--no-inc` is given. See [dnsfmt.1.md](dnsfmt.1.md) for the layout rules.

## Origin

`dnsfmt` started as a fork of [miekg/dnsfmt](https://github.com/miekg/dnsfmt)
(GPL-3.0), which builds on [bwesterb/go-zonefile](https://github.com/bwesterb/go-zonefile)
(LGPL-3.0). The layout they established is kept; the code behind the command
is now go-masterfile, an independent Apache-2.0 implementation, so nothing
of either project remains in this repository.
