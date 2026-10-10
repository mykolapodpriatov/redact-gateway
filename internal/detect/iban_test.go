package detect_test

import (
	"testing"

	"redact-gateway/internal/detect"
)

func TestIBANValid(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"gb", "GB82WEST12345698765432", true},
		{"de", "DE89370400440532013000", true},
		{"spaces", "GB82 WEST 1234 5698 7654 32", true},
		{"badCheckGB", "GB82WEST12345698765433", false},
		{"badCheckDE", "DE89370400440532013001", false},
		{"shapeOnly", "AB12CDEFGHIJKLMNO", false},
		{"lowercase", "gb82west12345698765432", false},
		{"tooShort", "GB82WEST", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := detect.IBANValid(tc.in); got != tc.want {
				t.Fatalf("IBANValid(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
