package registry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sampleData() Data {
	return Data{
		DefaultBot: "example_login",
		Bots: map[string]Bot{
			"example_login": {ClientID: "111", ClientSecret: "bot-secret-shared"},
			"kotlin-app":    {ClientID: "222", ClientSecret: "bot-secret-own"},
		},
		Clients: map[string]Client{
			"kotlin-app": {Secret: "app-secret-p", Bot: "kotlin-app"},
			"go-app":     {Secret: "app-secret-m"},
			"web-app":    {Secret: "app-secret-s", RedirectOrigins: []string{"https://web-app.example.com"}},
		},
		Slugs: map[string]Slug{
			"kotlin-app-dev": {Bot: "kotlin-app", SecretToken: "st-1", AgentToken: "at-1"},
		},
	}
}

func newTestRegistry(t *testing.T) (*Registry, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "registry.json")
	box, err := NewBox(testKey())
	if err != nil {
		t.Fatal(err)
	}
	r, err := Create(path, box, sampleData())
	if err != nil {
		t.Fatalf("Create() = %v", err)
	}
	return r, path
}

func TestResolveClientFallsBackToDefaultBot(t *testing.T) {
	r, _ := newTestRegistry(t)

	c, bot, err := r.ResolveClient("go-app")
	if err != nil {
		t.Fatalf("ResolveClient(go-app) = %v", err)
	}
	if c.Secret != "app-secret-m" {
		t.Errorf("client secret = %q", c.Secret)
	}
	if bot.ClientID != "111" {
		t.Errorf("bot = %+v, want the default bot", bot)
	}
}

func TestResolveClientPrefersItsOwnBot(t *testing.T) {
	r, _ := newTestRegistry(t)

	_, bot, err := r.ResolveClient("kotlin-app")
	if err != nil {
		t.Fatalf("ResolveClient(kotlin-app) = %v", err)
	}
	if bot.ClientID != "222" {
		t.Errorf("bot = %+v, want the client's own bot", bot)
	}
}

func TestResolveClientRefusesAnUnregisteredClient(t *testing.T) {
	r, _ := newTestRegistry(t)

	// Layer 1: an application nobody registered is turned away here, before the
	// broker ever talks to Telegram on its behalf.
	if _, _, err := r.ResolveClient("some-other-app"); err == nil {
		t.Error("ResolveClient() accepted an unregistered client_id")
	}
}

func TestValidateRejectsAClientPointingAtAMissingBot(t *testing.T) {
	d := sampleData()
	d.Clients["kotlin-app"] = Client{Secret: "x", Bot: "does-not-exist"}
	if err := Validate(d); err == nil {
		t.Error("Validate() accepted a client referencing an unknown bot")
	}
}

func TestValidateRejectsAMissingDefaultBot(t *testing.T) {
	d := sampleData()
	d.DefaultBot = "gone"
	if err := Validate(d); err == nil {
		t.Error("Validate() accepted a default_bot that is not in bots")
	}
}

func TestValidateRejectsTwoSlugsOnOneBot(t *testing.T) {
	// setWebhook is a global property of a bot: one bot is one URL is one buffer.
	// Two slugs on the same bot would silently mix two projects' updates, so the
	// broker refuses to start instead.
	d := sampleData()
	d.Slugs["go-app-dev"] = Slug{Bot: "kotlin-app", SecretToken: "st-2", AgentToken: "at-2"}
	err := Validate(d)
	if err == nil {
		t.Fatal("Validate() accepted two slugs bound to one bot")
	}
	if !strings.Contains(err.Error(), "kotlin-app") {
		t.Errorf("Validate() error %q does not name the bot that is doubly bound", err)
	}
}

func TestValidateRejectsANonLoopbackOriginThatIsNotAnOrigin(t *testing.T) {
	d := sampleData()
	d.Clients["web-app"] = Client{Secret: "x", RedirectOrigins: []string{"https://app.example.com/callback"}}
	if err := Validate(d); err == nil {
		t.Error("Validate() accepted an allow-list entry carrying a path")
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	_, path := newTestRegistry(t)
	box, _ := NewBox(testKey())

	r, err := Load(path, box)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	c, bot, err := r.ResolveClient("kotlin-app")
	if err != nil {
		t.Fatalf("ResolveClient() after Load = %v", err)
	}
	if c.Secret != "app-secret-p" || bot.ClientSecret != "bot-secret-own" {
		t.Errorf("round trip lost secrets: client=%+v bot=%+v", c, bot)
	}
}

func TestSecretsAreNotInTheFileInClear(t *testing.T) {
	_, path := newTestRegistry(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"bot-secret-shared", "bot-secret-own", "app-secret-p", "app-secret-m", "st-1", "at-1"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("registry file contains %q in clear", secret)
		}
	}
	// The structure itself stays readable by eye — that is the whole argument for
	// a JSON file over a database.
	if !strings.Contains(string(raw), "kotlin-app") {
		t.Error("registry file does not name its clients; it is not readable by eye")
	}
}

func TestLoadWithTheWrongKeyFails(t *testing.T) {
	_, path := newTestRegistry(t)
	other := testKey()
	other[0] ^= 0xff
	box, _ := NewBox(other)

	if _, err := Load(path, box); err == nil {
		t.Error("Load() succeeded with the wrong encryption key")
	}
}

func TestLoadRefusesACorruptFileWithoutTouchingIt(t *testing.T) {
	_, path := newTestRegistry(t)
	before, _ := os.ReadFile(path)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	box, _ := NewBox(testKey())

	if _, err := Load(path, box); err == nil {
		t.Fatal("Load() accepted a corrupt file")
	}
	after, _ := os.ReadFile(path)
	if string(after) != "{not json" {
		t.Errorf("Load() rewrote a file it could not read; before=%q after=%q", before, after)
	}
}

func TestUpdateAppliesWithoutRestartAndPersists(t *testing.T) {
	r, path := newTestRegistry(t)

	err := r.Update(func(d *Data) error {
		d.Clients["newcomer"] = Client{Secret: "app-secret-n"}
		return nil
	})
	if err != nil {
		t.Fatalf("Update() = %v", err)
	}
	// Live snapshot: no reload, no restart.
	if _, _, err := r.ResolveClient("newcomer"); err != nil {
		t.Errorf("ResolveClient(newcomer) = %v right after Update", err)
	}
	box, _ := NewBox(testKey())
	reloaded, err := Load(path, box)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := reloaded.ResolveClient("newcomer"); err != nil {
		t.Errorf("the change did not survive a reload: %v", err)
	}
}

func TestUpdateRollsBackAnInvalidChange(t *testing.T) {
	r, path := newTestRegistry(t)
	before, _ := os.ReadFile(path)

	err := r.Update(func(d *Data) error {
		d.Clients["broken"] = Client{Secret: "x", Bot: "does-not-exist"}
		return nil
	})
	if err == nil {
		t.Fatal("Update() accepted a change that fails validation")
	}
	if _, _, err := r.ResolveClient("broken"); err == nil {
		t.Error("the rejected client is live in the snapshot")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Error("Update() wrote the file despite rejecting the change")
	}
}

func TestSaveLeavesNoTemporaryFileBehind(t *testing.T) {
	r, path := newTestRegistry(t)
	if err := r.Update(func(d *Data) error { return nil }); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want only the registry file", names)
	}
}

func TestEnsureClientsUpsertsAndPersists(t *testing.T) {
	// Until the admin interface exists in phase 7, this is the only way to
	// register an application: put it in the environment and restart.
	r, path := newTestRegistry(t)

	err := r.EnsureClients(map[string]Client{
		"go-app":   {Secret: "rotated-secret"},
		"newcomer": {Secret: "app-secret-n", Bot: "kotlin-app"},
	})
	if err != nil {
		t.Fatalf("EnsureClients() = %v", err)
	}

	c, _, err := r.ResolveClient("newcomer")
	if err != nil || c.Secret != "app-secret-n" {
		t.Errorf("newcomer not registered: %v %+v", err, c)
	}
	if c, _, _ := r.ResolveClient("go-app"); c.Secret != "rotated-secret" {
		t.Errorf("go-app secret = %q, want the rotated one", c.Secret)
	}
	// Clients that were already there and are not mentioned stay untouched.
	if _, _, err := r.ResolveClient("kotlin-app"); err != nil {
		t.Errorf("an unmentioned client disappeared: %v", err)
	}

	box, _ := NewBox(testKey())
	reloaded, err := Load(path, box)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := reloaded.ResolveClient("newcomer"); err != nil {
		t.Errorf("the change did not survive a reload: %v", err)
	}
}

func TestEnsureClientsRejectsAnInvalidClient(t *testing.T) {
	r, _ := newTestRegistry(t)

	if err := r.EnsureClients(map[string]Client{"broken": {Secret: "x", Bot: "nope"}}); err == nil {
		t.Error("EnsureClients() accepted a client pointing at a bot that does not exist")
	}
	if _, _, err := r.ResolveClient("broken"); err == nil {
		t.Error("the rejected client is live")
	}
}

func TestEnsureClientsIsANoOpWhenNothingIsGiven(t *testing.T) {
	r, path := newTestRegistry(t)
	before, _ := os.ReadFile(path)

	if err := r.EnsureClients(nil); err != nil {
		t.Fatalf("EnsureClients(nil) = %v", err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Error("EnsureClients(nil) rewrote the file")
	}
}
