package names

import "testing"

func TestValidate(t *testing.T) {
	ok := []string{"abc", "my_app", "a12", "xyz_123"}
	for _, n := range ok {
		if err := Validate(n); err != nil {
			t.Errorf("%q: unexpected error %v", n, err)
		}
	}
	bad := []string{"", "ab", "1abc", "Abc", "a-b", "a b", `a"b`, "a;b", "ab'c", "pg_foo", "pgpanel_staging_1", "postgres", "pgpanel", "tenants", "template1", "public",
		"a234567890123456789012345678901234567890123456789012345678901234"}
	for _, n := range bad {
		if err := Validate(n); err == nil {
			t.Errorf("%q: expected error", n)
		}
	}
}
