package oidc

// Identity is everything the broker learned about the person who logged in, and
// everything it is willing to hand on. Nothing bot-related travels with it: the
// bot credentials never leave the broker.
type Identity struct {
	// ID is the Telegram user id. Both consumers read it from the id_token's
	// non-standard "id" claim; sub is a different number and must never stand in
	// for it.
	ID       int64
	Name     string
	Username string
	PhotoURL string
}
