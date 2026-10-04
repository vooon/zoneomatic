package dnsfmt

import "strconv"

// Quote renders a raw character-string as a quoted zone file string.
// Backslashes and quotes are escaped and control bytes use \DDD, so the
// value cannot break out of its quotes and reads back unchanged. Other bytes
// (including UTF-8) are kept as is.
//
// Go's %q is not suitable: zone file parsers do not understand \n, \x or \u.
func Quote(v []byte) string {
	b := make([]byte, 0, len(v)+2)
	b = append(b, '"')
	for _, c := range v {
		switch {
		case c == '"' || c == '\\':
			b = append(b, '\\', c)
		case c < 0x20 || c == 0x7f:
			b = append(b, '\\')
			if c < 100 {
				b = append(b, '0')
			}
			if c < 10 {
				b = append(b, '0')
			}
			b = strconv.AppendUint(b, uint64(c), 10)
		default:
			b = append(b, c)
		}
	}
	return string(append(b, '"'))
}
