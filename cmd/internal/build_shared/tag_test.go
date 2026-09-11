package build_shared

import (
	"os/exec"
	"strings"
	"testing"
)

func TestVersionTags(t *testing.T) {
	for _, version := range []string{"1.14.0", "1.14.0-rc.1"} {
		t.Run(version, func(t *testing.T) {
			t.Chdir(t.TempDir())
			git := func(args ...string) string {
				t.Helper()
				output, err := exec.Command("git", args...).CombinedOutput()
				if err != nil {
					t.Fatalf("git %v: %v\n%s", args, err, output)
				}
				return strings.TrimSpace(string(output))
			}
			git("init", "--quiet")
			git("config", "user.name", "Test")
			git("config", "user.email", "test@example.invalid")
			git("config", "commit.gpgsign", "false")
			git("config", "tag.gpgsign", "false")
			git("commit", "--quiet", "--allow-empty", "-m", "version")
			git("tag", "v"+version)

			check := func(wantTag, wantVersion string) {
				t.Helper()
				got, err := ReadTag()
				if err != nil || got != wantTag {
					t.Fatalf("ReadTag() = %q, %v; want %q", got, err, wantTag)
				}
				rev, err := ReadTagVersionRev()
				if err != nil || rev.String() != version {
					t.Fatalf("ReadTagVersionRev() = %s, %v; want %s", rev, err, version)
				}
				next, err := ReadTagVersion()
				if err != nil || next.String() != wantVersion {
					t.Fatalf("ReadTagVersion() = %s, %v; want %s", next, err, wantVersion)
				}
			}
			check(version, version)

			git("commit", "--quiet", "--allow-empty", "-m", "self-test")
			git("tag", "rc-test")
			git("tag", "version")
			wantVersion := version
			if version == "1.14.0" {
				wantVersion = "1.14.1"
			}
			check(version+"-"+git("rev-parse", "--short", "HEAD"), wantVersion)

			git("tag", "-d", "v"+version)
			if _, err := ReadTag(); err == nil {
				t.Fatal("ReadTag() should fail when only non-version tags exist")
			}
		})
	}
}
