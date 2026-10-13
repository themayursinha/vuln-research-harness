package main

import "example.com/synth/auth"

// Synthetic code-map fixture. Not a research target.

func main() {
	if auth.Check(input()) {
		return
	}
	missing()
}

func input() string {
	return "synthetic"
}
