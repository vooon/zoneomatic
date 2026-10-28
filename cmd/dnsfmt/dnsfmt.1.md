% DNSFMT(1) dnsfmt | System Administration
% Vladimir Ermakov, Miek Gieben
% October 2026

# NAME

dnsfmt - format DNS zone files

# SYNOPSIS

**dnsfmt** [**--no-inc**] [**-o** *ORIGIN*] [**-r**] [*FILE*]...

# DESCRIPTION

**dnsfmt** formats zone files in the layout zoneomatic writes. Without *FILE*
(or with `-`) it reads standard input and prints the result. The ordering of
the file is kept, as are all comments and `$`-directives.

The layout rules:

- owner names are written relative to the `$ORIGIN` in effect and aligned in a
  column (long names overflow it); a repeated owner is left blank, but is
  written again after a comment, a blank line or a directive;
- a TTL column only appears for records whose TTL differs from the `$TTL` in
  effect; a TTL equal to it is redundant and dropped;
- classes and types are upper-cased and aligned; values are written as they
  are, nothing is rewritten;
- TXT strings are written quoted and escaped; long DNSKEY, DS and RRSIG data
  is wrapped in parentheses;
- the SOA record is written one field per line with its name as a comment,
  the serial also with its date (Unix time or `YYYYMMDDnn`);
- comments stay next to the value they follow; blank lines are kept, runs
  collapsed to one;
- `$ORIGIN` is always written fully qualified.

No semantic checks are done. zoneomatic verifies its own writes with an
independent parser; **dnsfmt** does not.

# OPTIONS

`-o`, `--origin` *ORIGIN*
: the zone origin before the first `$ORIGIN` directive; by default taken from
  the file (`$ORIGIN`, or the SOA owner).

`-i`, `--inc` / `--no-inc`
: bump the SOA serial (default). A Unix-time serial becomes the current time,
  always increasing; a `YYYYMMDDnn` serial is incremented by one.

`-r`, `--replace`
: rewrite the files in place (atomically) instead of printing.

# EXAMPLE

    % cat <<'EOF' | dnsfmt --no-inc
    $TTL 6H
    $ORIGIN example.org.
    @       IN      SOA     ns miek.miek.nl. 1282630067  4H 1H 7D 7200
                    IN      NS  ns
    example.org.            IN      NS  ns-ext.nlnetlabs.nl.
    www  21600 IN A 192.0.2.1
    EOF

Returns:

    $TTL 6H
    $ORIGIN example.org.
    @   IN SOA ns miek.miek.nl. (
        1282630067 ; serial  Tue, 24 Aug 2010 06:07:47 UTC
        4H         ; refresh
        1H         ; retry
        7D         ; expire
        7200       ; minimum
    )
        IN NS  ns
        IN NS  ns-ext.nlnetlabs.nl.
    www IN A   192.0.2.1

The TTL of `www` equals `$TTL` and is dropped.

# AUTHORS

Originally written by Miek Gieben as **dnsfmt**; reworked for zoneomatic by
Vladimir Ermakov.
