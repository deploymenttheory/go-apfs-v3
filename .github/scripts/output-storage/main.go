// Command output-storage verifies downloaded host artifacts and shares storage
// for identical immutable files before the next host's archive is extracted.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/native"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func main() {
	root := flag.String("root", "", "downloaded host artifact directory")
	producer := flag.Int("producer", 0, "native producer major")
	selected := flag.String("hosts", "", "comma-separated downloaded portable hosts")
	flag.Parse()
	if *root == "" || !schema.IsSupportedProducer(*producer) || *selected == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "root, supported producer and hosts are required")
		os.Exit(2)
	}
	dirs := map[string]string{}
	for _, host := range strings.Split(*selected, ",") {
		if host != "linux" && host != "windows" && host != "darwin" {
			fmt.Fprintln(os.Stderr, "unknown output host")
			os.Exit(2)
		}
		dirs[host] = filepath.Join(*root, fmt.Sprintf("outputs-%s-macos-%d", host, *producer))
	}
	outputs, err := native.LoadOutputs(dirs, *producer)
	var shared int64
	if err == nil {
		shared, err = native.ShareIdenticalOutputs(outputs)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("Verified %s output digests; shared %d bytes of identical storage before further downloads\n", *selected, shared)
}
