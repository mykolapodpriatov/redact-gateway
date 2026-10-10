package detect

// IBANValid reports whether s is a structurally valid IBAN under ISO 13616.
//
// Spaces are stripped. The remainder must be 15-34 characters: a two-letter
// country code, two check digits, then an alphanumeric BBAN. Letters must be
// upper case. The ISO 7064 mod-97 checksum has to come out as 1, which is the
// same idea as LuhnValid on the card pattern: a token that merely looks like
// an IBAN (an invoice reference, a booking code) is not masked.
func IBANValid(s string) bool {
	compact := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			continue
		}
		compact = append(compact, s[i])
	}
	n := len(compact)
	if n < 15 || n > 34 {
		return false
	}
	if !isUpper(compact[0]) || !isUpper(compact[1]) || !isDigit(compact[2]) || !isDigit(compact[3]) {
		return false
	}
	for _, c := range compact[4:] {
		if !isUpper(c) && !isDigit(c) {
			return false
		}
	}

	// Move the country code and check digits to the end, then walk the
	// expanded digit string modulo 97. A valid IBAN leaves a remainder of 1.
	rearranged := make([]byte, n)
	copy(rearranged, compact[4:])
	copy(rearranged[n-4:], compact[:4])
	mod := 0
	for _, c := range rearranged {
		if isDigit(c) {
			mod = (mod*10 + int(c-'0')) % 97
			continue
		}
		value := int(c-'A') + 10
		mod = (mod*10 + value/10) % 97
		mod = (mod*10 + value%10) % 97
	}
	return mod == 1
}

func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }
