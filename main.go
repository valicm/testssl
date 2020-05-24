package main

import (
	"flag"
	"github.com/valicm/testssl/ssl"
)

var (
	domain = flag.String("domain", "", "Domain for which you wish to generate SSL")
	dir    = flag.String("dir", "ssl", "Directory where you want to generate SSL")
)

func main() {
	flag.Parse()
	ssl.GenerateCert(*domain, *dir)
}
