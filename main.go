package main

import (
	"flag"
	"testssl/testssl"
)

var (
	domain = flag.String("domain", "", "Domain for which you wish to generate SSL")
	dir    = flag.String("dir", "ssl", "Directory where you want to generate SSL")
)

func main() {
	testssl.Execute(*domain, *dir)
}
