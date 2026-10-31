// Command h1-keygen prints a fresh random PSK as hex, for pasting into both
// the server and client config files.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		fmt.Fprintln(os.Stderr, "keygen:", err)
		os.Exit(1)
	}
	fmt.Println(hex.EncodeToString(key))
}
