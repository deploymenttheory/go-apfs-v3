package receipt

import (
	"fmt"
	"regexp"
	"strings"
)

// Selector follows go test's slash-separated and top-level-alternation syntax.
// Separators inside brackets, parentheses and escapes remain part of a regex.
// See the Go distribution's src/testing/match.go (BSD-licensed Go authors).
// Keeping this behavior explicit prevents a successful parent test from hiding
// that a selected child never ran.
type Selector [][]*regexp.Regexp

func ParseSelector(text string) (Selector, error) {
	var result Selector
	var parts []*regexp.Regexp
	start, brackets, parentheses := 0, 0, 0
	appendPart := func(end int) error {
		expression, err := regexp.Compile(text[start:end])
		if err != nil {
			return fmt.Errorf("invalid test selector: %w", err)
		}
		parts = append(parts, expression)
		start = end + 1
		return nil
	}
	for index := 0; index < len(text); index++ {
		switch text[index] {
		case '\\':
			index++
		case '[':
			brackets++
		case ']':
			brackets = max(0, brackets-1)
		case '(':
			if brackets == 0 {
				parentheses++
			}
		case ')':
			if brackets == 0 {
				parentheses--
			}
		case '/', '|':
			if brackets != 0 || parentheses != 0 {
				continue
			}
			if err := appendPart(index); err != nil {
				return nil, err
			}
			if text[index] == '|' {
				result = append(result, parts)
				parts = nil
			}
		}
	}
	if err := appendPart(len(text)); err != nil {
		return nil, err
	}
	return append(result, parts), nil
}

func (s Selector) Match(name string, partial bool) bool {
	segments := strings.Split(name, "/")
	for _, alternative := range s {
		matches := true
		if !partial && len(segments) < len(alternative) {
			continue
		}
		for n := 0; n < min(len(segments), len(alternative)); n++ {
			matches = matches && alternative[n].MatchString(segments[n])
		}
		if matches {
			return true
		}
	}
	return false
}
