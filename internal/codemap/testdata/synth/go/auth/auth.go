package auth

// Synthetic code-map fixture. Not a research target.

type Gate struct{}

func Check(s string) bool {
	var g Gate
	return g.Allow(s)
}

func (g *Gate) Allow(s string) bool {
	return normalize(s)
}

func normalize(s string) bool {
	return len(s) > 0
}
