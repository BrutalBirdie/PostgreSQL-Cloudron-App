package names

import (
	"errors"
	"regexp"
	"strings"
)

var pattern = regexp.MustCompile(`^[a-z][a-z0-9_]{2,62}$`)

var reserved = map[string]bool{
	"postgres":  true,
	"pgpanel":   true,
	"tenants":   true,
	"template0": true,
	"template1": true,
	"public":    true,
}

var ErrInvalid = errors.New("use 3 to 63 characters a-z, 0-9 and _, starting with a letter")
var ErrReserved = errors.New("this name is reserved")

// Validate is applied to every role and database name before it reaches SQL.
func Validate(name string) error {
	if !pattern.MatchString(name) {
		return ErrInvalid
	}
	if reserved[name] || strings.HasPrefix(name, "pg_") {
		return ErrReserved
	}
	return nil
}
