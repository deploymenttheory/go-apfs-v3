package main

import (
	"errors"
	"os"
	"path/filepath"
)

func physicalPath(name string) (string, error) {
	name, err := filepath.Abs(name)
	if err != nil {
		return "", err
	}
	var tail []string
	for {
		physical, err := filepath.EvalSymlinks(name)
		if err == nil {
			for n := len(tail) - 1; n >= 0; n-- {
				physical = filepath.Join(physical, tail[n])
			}
			return physical, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(name)
		if parent == name {
			return "", err
		}
		tail = append(tail, filepath.Base(name))
		name = parent
	}
}

func separatePaths(input, output string) error {
	input, err := physicalPath(input)
	if err != nil {
		return err
	}
	output, err = physicalPath(output)
	if err != nil {
		return err
	}
	for _, pair := range [][2]string{{input, output}, {output, input}} {
		relative, err := filepath.Rel(pair[0], pair[1])
		if err == nil && (relative == "." || filepath.IsLocal(relative)) {
			return errors.New("replay writable output and immutable inputs overlap")
		}
	}
	return nil
}
