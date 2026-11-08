package kt

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnvOrDefaultStr(t *testing.T) {
	t.Setenv("KTMAN_TEST_VAR", "")
	if got := EnvOrDefaultStr("KTMAN_TEST_VAR", "def"); got != "def" {
		t.Errorf("empty: got %q, want the default", got)
	}

	t.Setenv("KTMAN_TEST_VAR", "set")
	if got := EnvOrDefaultStr("KTMAN_TEST_VAR", "def"); got != "set" {
		t.Errorf("set: got %q", got)
	}
}

func TestResolveKeytabPath(t *testing.T) {
	for _, c := range []struct{ env, flag, want string }{
		{"", "", ""},
		{"/env.keytab", "", "/env.keytab"},
		{"FILE:/env.keytab", "", "/env.keytab"},
		{"WRFILE:/env.keytab", "", "/env.keytab"},
		{"/env.keytab", "flag.keytab", "flag.keytab"},
	} {
		t.Setenv(EnvKeytab, c.env)

		got, err := ResolveKeytabPath(c.flag)
		if err != nil || got != c.want {
			t.Errorf("%s=%q -k %q: got %q, %v; want %q", EnvKeytab, c.env, c.flag, got, err, c.want)
		}
	}

	t.Setenv(EnvKeytab, "MEMORY:x")
	if _, err := ResolveKeytabPath(""); err == nil {
		t.Error("a MEMORY: keytab is not a file")
	}
}

func TestResolveConfigPath(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "krb5.conf")
	if err := os.WriteFile(conf, []byte("[libdefaults]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	missing := filepath.Join(dir, "missing.conf")

	for _, c := range []struct{ env, flag, want string }{
		{"", "", DefaultConfigPath},
		{conf, "", conf},
		{conf, "other.conf", "other.conf"},
		{missing + string(os.PathListSeparator) + conf, "", conf},
		{missing, "", missing},
	} {
		t.Setenv(EnvConfig, c.env)

		if got := ResolveConfigPath(c.flag); got != c.want {
			t.Errorf("%s=%q -c %q: got %q, want %q", EnvConfig, c.env, c.flag, got, c.want)
		}
	}
}
