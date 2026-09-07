package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// The on-disk shape mirrors §5 of the plan, so the file reads the way the plan
// describes it. Secrets are sealed; names and structure stay in the clear on
// purpose — being readable and restorable by hand is the whole argument for a
// file over a database.
type fileDoc struct {
	Login struct {
		DefaultBot string                `json:"default_bot"`
		Bots       map[string]fileBot    `json:"bots"`
		Clients    map[string]fileClient `json:"clients"`
	} `json:"login"`
	Relay struct {
		Slugs map[string]fileSlug `json:"slugs"`
	} `json:"relay"`
}

type fileBot struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type fileClient struct {
	Secret          string   `json:"secret"`
	Bot             string   `json:"bot,omitempty"`
	RedirectOrigins []string `json:"redirect_origins,omitempty"`
}

type fileSlug struct {
	Bot         string `json:"bot"`
	SecretToken string `json:"secret_token"`
	AgentToken  string `json:"agent_token"`
}

// Create writes a fresh registry and returns it live.
func Create(path string, box *Box, data Data) (*Registry, error) {
	data = data.clone()
	if err := Validate(data); err != nil {
		return nil, err
	}
	if err := save(path, box, data); err != nil {
		return nil, err
	}
	return &Registry{data: data, path: path, box: box}, nil
}

// Load reads an existing registry. Every failure here is fatal by design: a
// registry that cannot be read must never be replaced by an empty one, because
// an empty registry is a broker that turns every application away.
func Load(path string, box *Box) (*Registry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc fileDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("registry %s is not valid JSON: %w", path, err)
	}

	data := Data{
		DefaultBot: doc.Login.DefaultBot,
		Bots:       make(map[string]Bot, len(doc.Login.Bots)),
		Clients:    make(map[string]Client, len(doc.Login.Clients)),
		Slugs:      make(map[string]Slug, len(doc.Relay.Slugs)),
	}
	for name, b := range doc.Login.Bots {
		secret, err := box.Open(b.ClientSecret)
		if err != nil {
			return nil, fmt.Errorf("registry %s: bot %q: %w", path, name, err)
		}
		data.Bots[name] = Bot{ClientID: b.ClientID, ClientSecret: secret}
	}
	for name, c := range doc.Login.Clients {
		secret, err := box.Open(c.Secret)
		if err != nil {
			return nil, fmt.Errorf("registry %s: client %q: %w", path, name, err)
		}
		data.Clients[name] = Client{Secret: secret, Bot: c.Bot, RedirectOrigins: c.RedirectOrigins}
	}
	for name, s := range doc.Relay.Slugs {
		secretToken, err := box.Open(s.SecretToken)
		if err != nil {
			return nil, fmt.Errorf("registry %s: slug %q secret_token: %w", path, name, err)
		}
		agentToken, err := box.Open(s.AgentToken)
		if err != nil {
			return nil, fmt.Errorf("registry %s: slug %q agent_token: %w", path, name, err)
		}
		data.Slugs[name] = Slug{Bot: s.Bot, SecretToken: secretToken, AgentToken: agentToken}
	}

	if err := Validate(data); err != nil {
		return nil, fmt.Errorf("registry %s: %w", path, err)
	}
	return &Registry{data: data, path: path, box: box}, nil
}

func save(path string, box *Box, data Data) error {
	var doc fileDoc
	doc.Login.DefaultBot = data.DefaultBot
	doc.Login.Bots = make(map[string]fileBot, len(data.Bots))
	doc.Login.Clients = make(map[string]fileClient, len(data.Clients))
	doc.Relay.Slugs = make(map[string]fileSlug, len(data.Slugs))

	for name, b := range data.Bots {
		sealed, err := box.Seal(b.ClientSecret)
		if err != nil {
			return err
		}
		doc.Login.Bots[name] = fileBot{ClientID: b.ClientID, ClientSecret: sealed}
	}
	for name, c := range data.Clients {
		sealed, err := box.Seal(c.Secret)
		if err != nil {
			return err
		}
		doc.Login.Clients[name] = fileClient{Secret: sealed, Bot: c.Bot, RedirectOrigins: c.RedirectOrigins}
	}
	for name, s := range data.Slugs {
		secretToken, err := box.Seal(s.SecretToken)
		if err != nil {
			return err
		}
		agentToken, err := box.Seal(s.AgentToken)
		if err != nil {
			return err
		}
		doc.Relay.Slugs[name] = fileSlug{Bot: s.Bot, SecretToken: secretToken, AgentToken: agentToken}
	}

	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, append(raw, '\n'))
}

// writeAtomic writes into the destination directory and renames over the target,
// so a crash mid-write leaves the old registry intact rather than a truncated
// one. Same directory matters: rename is only atomic within a filesystem.
func writeAtomic(path string, content []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".registry-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeded

	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
