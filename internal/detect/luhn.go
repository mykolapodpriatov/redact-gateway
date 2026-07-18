package detect

// LuhnValid reports whether the digit run in s passes the Luhn (mod-10)
// checksum after stripping ASCII spaces and hyphens, requiring 13-19 digits
// (the ISO/IEC 7812 primary-account-number length range). Any rune that is not
// a digit, space, or hyphen makes it return false.
//
// It is wired as the Validate hook on the default "card" PII pattern so that
// arbitrary 13-19 digit runs — order numbers, IMEIs, account/tracking IDs, and
// long serials — are no longer masked as payment cards. It is exported so
// custom patterns can opt into the same checksum gate.
func LuhnValid(s string) bool {
	sum := 0
	count := 0
	double := false
	// Walk right-to-left so the doubling alignment is independent of length.
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		switch {
		case c == ' ' || c == '-':
			continue
		case c >= '0' && c <= '9':
			d := int(c - '0')
			count++
			if double {
				d *= 2
				if d > 9 {
					d -= 9
				}
			}
			sum += d
			double = !double
		default:
			// A non-digit, non-separator rune means this is not a bare PAN.
			return false
		}
	}
	if count < 13 || count > 19 {
		return false
	}
	return sum%10 == 0
}
