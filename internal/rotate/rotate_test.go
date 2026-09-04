package rotate

import "testing"

func TestHintKnownTypes(t *testing.T) {
	for _, typ := range []string{
		"slack_webhook", "discord_bot_token", "telegram_bot_token",
		"azure_storage_key", "datadog_api_key", "digitalocean_token", "basic_auth",
	} {
		if Hint(typ) == Fallback {
			t.Fatalf("missing rotation hint for %s", typ)
		}
	}
}
