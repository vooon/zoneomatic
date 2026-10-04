package dnsfmt

import (
	"strconv"
	"time"
)

// isEpoch reports whether a serial is a Unix timestamp rather than the
// YYYYMMDDnn date convention (RFC 1912). Only serials that form a plausible
// date (year 1990-2099, valid month and day) are taken as dates. This does
// not depend on the current time, unlike a "close to now" window, which
// misclassifies old epoch serials.
func isEpoch(i int64) bool {
	if i < 1990010100 || i > 2099123199 {
		return true
	}
	date := i / 100
	year, month, day := int(date/10000), time.Month(date/100%100), int(date%100)
	t := time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
	return t.Year() != year || t.Month() != month || t.Day() != day
}

func Increase(s []byte) []byte {
	i, err := strconv.ParseInt(string(s), 10, 64)
	if err != nil {
		return s
	}
	if isEpoch(i) { // return current epoch, but always move forward
		e := max(time.Now().Unix(), i+1)
		return []byte(strconv.FormatInt(e, 10))
	}
	// otherwise just increase? TODO(miek): smarter later
	i++
	return []byte(strconv.FormatInt(i, 10))
}

// SerialToHuman will detect if a number is epoch, or a coded date, ie:
//
// 1712989081 is epoch, because, when converted is less than 15 years ago, and not more than
// 5 years in the future.
//
// If not epoch, we assume a "date" format: 2024041300. Every sequence number 00, 01, is
// assumed to be an hour.
//
// Both are converted to a more human readable string.
func SerialToHuman(s []byte) string {
	i, err := strconv.ParseInt(string(s), 10, 64)
	if err != nil {
		return "  " + dateToHuman(s)
	}
	if !isEpoch(i) {
		return "  " + dateToHuman(s)
	}
	return "  " + time.Unix(i, 0).UTC().Format(time.RFC1123)
}

func dateToHuman(s []byte) string {
	if len(s) != 10 { // e.g. 2024041300
		return ""
	}
	year, _ := strconv.ParseInt(string(s[:4]), 10, 64)
	mon, _ := strconv.ParseInt(string(s[4:6]), 10, 64)
	day, _ := strconv.ParseInt(string(s[6:8]), 10, 64)
	sequence, _ := strconv.ParseInt(string(s[8:10]), 10, 64)
	// sequence is considered the percentage the day has aged.
	// calculate total minutes and round to hour and remaining minutes
	minutes := 1440 / 100 * sequence
	hour := minutes / 60
	minutes -= hour * 60

	t := time.Date(int(year), time.Month(mon), int(day), int(hour), int(minutes), 0, 0, time.UTC)
	return t.Format(time.RFC1123)
}
