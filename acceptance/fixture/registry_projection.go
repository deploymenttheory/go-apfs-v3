package fixture

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

const retainedRegistryPathLimit = 16 << 10

type registryPathData []byte

// IORegistry contains opaque data and other values that plutil cannot always
// convert to JSON. Project only the ownership keys from the original archive;
// unused properties are skipped as bounded, well-formed XML, never decoded or
// interpreted as ownership. The complete original bytes remain in Transcript.
func decodeRegistryOwnership(raw []byte) ([]map[string]any, error) {
	if len(raw) == 0 || len(raw) > retainedRegistryTextLimit {
		return nil, errors.New("kernel registry archive size outside bounds")
	}
	p := registryProjection{decoder: xml.NewDecoder(bytes.NewReader(raw))}
	if err := p.expectStart("plist"); err != nil {
		return nil, err
	}
	if err := p.expectStart("array"); err != nil {
		return nil, err
	}
	items, err := p.nodes()
	if err != nil {
		return nil, err
	}
	if token, err := p.next(); err != nil || !registryEnd(token, "plist") {
		return nil, fmt.Errorf("kernel registry missing plist end: %v", err)
	}
	if _, err := p.next(); err != io.EOF {
		return nil, errors.New("kernel registry archive has trailing content")
	}
	roots := make([]map[string]any, 0, len(items))
	for _, item := range items {
		roots = append(roots, item.(map[string]any)) // nodes admits dictionaries only.
	}
	return roots, nil
}

type registryProjection struct {
	decoder       *xml.Decoder
	tokens, depth int
}

func (p *registryProjection) token() (xml.Token, error) {
	token, err := p.decoder.Token()
	if err != nil {
		return nil, err
	}
	p.tokens++
	if p.tokens > 100000 {
		return nil, errors.New("kernel registry token limit")
	}
	switch token.(type) {
	case xml.StartElement:
		p.depth++
		if p.depth > 64 {
			return nil, errors.New("kernel registry depth limit")
		}
	case xml.EndElement:
		p.depth--
	}
	return token, nil
}

func (p *registryProjection) next() (xml.Token, error) {
	for {
		token, err := p.token()
		if err != nil {
			return nil, err
		}
		switch token := token.(type) {
		case xml.CharData:
			if strings.TrimSpace(string(token)) == "" {
				continue
			}
		case xml.Comment, xml.ProcInst, xml.Directive:
			continue
		}
		return token, nil
	}
}

func registryStart(token xml.Token, name string) bool {
	start, ok := token.(xml.StartElement)
	return ok && start.Name.Space == "" && start.Name.Local == name
}

func registryEnd(token xml.Token, name string) bool {
	end, ok := token.(xml.EndElement)
	return ok && end.Name.Space == "" && end.Name.Local == name
}

func (p *registryProjection) expectStart(name string) error {
	token, err := p.next()
	if err != nil || !registryStart(token, name) {
		return fmt.Errorf("kernel registry expected %s: %v", name, err)
	}
	return nil
}

// nodes consumes an already opened array, accepting dictionaries only.
func (p *registryProjection) nodes() ([]any, error) {
	items := make([]any, 0)
	for {
		token, err := p.next()
		if err != nil {
			return nil, err
		}
		if registryEnd(token, "array") {
			return items, nil
		}
		if !registryStart(token, "dict") {
			return nil, errors.New("kernel registry node is not a dictionary")
		}
		node, err := p.node()
		if err != nil {
			return nil, err
		}
		items = append(items, node)
	}
}

func (p *registryProjection) node() (map[string]any, error) {
	node := map[string]any{}
	for {
		token, err := p.next()
		if err != nil {
			return nil, err
		}
		if registryEnd(token, "dict") {
			return node, nil
		}
		if !registryStart(token, "key") {
			return nil, errors.New("kernel registry dictionary expected key")
		}
		key, err := p.text("key")
		if err != nil || key == "" {
			return nil, fmt.Errorf("kernel registry invalid key: %v", err)
		}
		token, err = p.next()
		if err != nil {
			return nil, err
		}
		if _, duplicate := node[key]; duplicate {
			return nil, fmt.Errorf("kernel registry duplicate ownership key %q", key)
		}
		switch key {
		case "IOObjectClass", "BSD Name", "DiskImageURL":
			if !registryStart(token, "string") {
				return nil, fmt.Errorf("kernel registry %s is not a string", key)
			}
			node[key], err = p.text("string")
		case "IORegistryEntryChildren":
			if !registryStart(token, "array") {
				return nil, errors.New("kernel registry children is not an array")
			}
			node[key], err = p.nodes()
		case "image-path":
			if !registryStart(token, "data") {
				return nil, errors.New("kernel image-path is not CFData")
			}
			var text string
			text, err = p.text("data")
			if err == nil {
				text = strings.Join(strings.Fields(text), "")
				if len(text) > base64.StdEncoding.EncodedLen(retainedRegistryPathLimit) {
					return nil, errors.New("kernel image-path exceeds its bounded length")
				}
				var path []byte
				path, err = base64.StdEncoding.Strict().DecodeString(text)
				if len(path) > retainedRegistryPathLimit {
					return nil, errors.New("kernel image-path exceeds its bounded length")
				}
				node[key] = registryPathData(path)
			}
		default:
			if _, ok := token.(xml.StartElement); !ok {
				return nil, errors.New("kernel registry property has no XML value")
			}
			// Include skipped values in the same token/depth budget. A nested
			// opaque dictionary cannot supply any projected ownership fields.
			depth := p.depth
			for err == nil && p.depth >= depth {
				_, err = p.token()
			}
		}
		if err != nil {
			return nil, err
		}
	}
}

func (p *registryProjection) text(name string) (string, error) {
	var value strings.Builder
	for {
		token, err := p.token()
		if err != nil {
			return "", err
		}
		if registryEnd(token, name) {
			return value.String(), nil
		}
		switch token := token.(type) {
		case xml.CharData:
			value.Write(token)
		case xml.Comment:
		default:
			return "", errors.New("kernel registry key/string has nested XML")
		}
	}
}
