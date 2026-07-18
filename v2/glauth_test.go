package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type testEnv struct {
	checkanonymousrootDSE bool
	checkTOTP             bool
	checkbindUPN          bool
	svcdn                 string
	svcdnnogroup          string
	otpdn                 string
	expectedinfo          string
	expectedaccount       string
	scopedaccount         string
	expectedfirstaccount  string
	expectedgroup         string
	checkemployeetype     string
}

func glauthBinary() string {
	if binary := os.Getenv("GLAUTH_TEST_BINARY"); binary != "" {
		return binary
	}

	qualified := filepath.Join("bin", runtime.GOOS+runtime.GOARCH, "glauth")
	if _, err := os.Stat(qualified); err == nil {
		return qualified
	}
	return "bin/glauth"
}

func TestProperBuild(t *testing.T) {
	info, err := os.Stat(glauthBinary())
	if err != nil {
		t.Fatal(err)
	}
	mode := uint32(info.Mode())
	if mode&0b001001001 == 0 {
		t.Fatalf("bad file mode: %b", mode)
	}
}

func TestConfigBackendRejectsPasswordlessUserBinds(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	configPath := filepath.Join(t.TempDir(), "passwordless.cfg")
	config := fmt.Sprintf(`debug = false

[ldap]
  enabled = true
  listen = "127.0.0.1:%d"
  tls = false

[ldaps]
  enabled = false

[backend]
  datastore = "config"
  baseDN = "dc=glauth,dc=com"

[behaviors]
  LimitFailedBinds = false

[[groups]]
  name = "svc"
  gidnumber = 5501

[[users]]
  name = "nopass"
  uidnumber = 5001
  primarygroup = 5501
    [[users.capabilities]]
    action = "search"
    object = "*"
`, port)
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}

	svc := startSvc(SD, glauthBinary(), "-c", configPath)
	defer stopSvc(svc)

	bindDN := "cn=nopass,dc=glauth,dc=com"
	for _, tc := range []struct {
		name     string
		password string
		want     string
	}{
		{name: "arbitrary password", password: "definitely-wrong", want: "exit status 49"},
		{name: "empty password", password: "", want: "exit status 53"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := doRunGetFirst(0, "ldapsearch", "-LLL", "-H", fmt.Sprintf("ldap://127.0.0.1:%d", port), "-D", bindDN, "-w", tc.password, "-x", "-b", "dc=glauth,dc=com", "(cn=nopass)")
			if got != tc.want {
				t.Fatalf("bind result = %q, want %q", got, tc.want)
			}
		})
	}
}

func ldapOnlyConfig(t *testing.T, source string) string {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}

	contents := string(data)
	sectionMarker := "\n[ldaps]\n"
	markerStart := strings.Index(contents, sectionMarker)
	if markerStart < 0 {
		t.Fatalf("%s has no [ldaps] section", source)
	}
	start := markerStart + 1
	relEnd := strings.Index(contents[start+len("[ldaps]"):], "\n[")
	if relEnd < 0 {
		t.Fatalf("%s has no section after [ldaps]", source)
	}
	end := start + len("[ldaps]") + relEnd
	section := contents[start:end]
	sectionWithoutLDAPS := strings.Replace(section, "enabled = true", "enabled = false", 1)
	if section == sectionWithoutLDAPS {
		t.Fatalf("%s [ldaps] section does not enable LDAPS", source)
	}

	contents = contents[:start] + sectionWithoutLDAPS + contents[end:]
	path := filepath.Join(t.TempDir(), filepath.Base(source))
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func batteryOfTests(t *testing.T, env *testEnv) {
	tests := []struct {
		Name  string
		Path  string
		Check func(t testing.TB)
	}{
		{
			Name: "searching for the 'hackers' user",
			Check: func(t testing.TB) {
				out := doRunGetFirst(RD, "ldapsearch", "-LLL", "-H", "ldap://localhost:3893", "-D", env.svcdn, "-w", "mysecret", "-x", "-bdc=glauth,dc=com", "cn=hackers")
				if got, want := out, env.expectedaccount; got != want {
					t.Fatalf("should find them in the 'superheros' group\ngot:  %s\nwant: %s", got, want)
				}
			},
		},
		{
			Name: "searching for the 'hackers' user without binding with a group",
			Check: func(t testing.TB) {
				if env.svcdnnogroup == "" {
					t.SkipNow()
				}
				out := doRunGetFirst(RD, "ldapsearch", "-LLL", "-H", "ldap://localhost:3893", "-D", env.svcdnnogroup, "-w", "mysecret", "-x", "-bdc=glauth,dc=com", "cn=hackers")
				if got, want := out, env.expectedaccount; got != want {
					t.Fatalf("should find them in the 'superheros' group\ngot:  %s\nwant: %s", got, want)
				}
			},
		},
		{
			Name: "searching for the 'hackers' user after binding using the account's UPN",
			Check: func(t testing.TB) {
				if !env.checkbindUPN {
					t.SkipNow()
				}
				out := doRunGetFirst(RD, "ldapsearch", "-LLL", "-H", "ldap://localhost:3893", "-D", "serviceuser@example.com", "-w", "mysecret", "-x", "-bdc=glauth,dc=com", "cn=hackers")
				if got, want := out, env.expectedaccount; got != want {
					t.Fatalf("should find them in the 'superheros' group\ngot:  %s\nwant: %s", got, want)
				}
			},
		},
		{
			Name: "querying the root SDE",
			Check: func(t testing.TB) {
				out := doRunGetSecond(RD, "ldapsearch", "-LLL", "-H", "ldap://localhost:3893", "-D", env.svcdn, "-w", "mysecret", "-x", "-s", "base", "(objectclass=*)")
				if got, want := out, env.expectedinfo; got != want {
					t.Fatalf("should get some meta information\ngot:  %s\nwant: %s", got, want)
				}
			},
		},
		{
			Name: "querying the root SDE anonymously without authorizing in config file",
			Check: func(t testing.TB) {
				if !env.checkanonymousrootDSE {
					t.SkipNow()
				}
				out := doRunGetFirst(RD, "ldapsearch", "-LLL", "-H", "ldap://localhost:3893", "-x", "-s", "base", "(objectclass=*)")
				if got, want := out, "exit status 50"; got != want {
					t.Fatalf("should get error 50\ngot:  %s\nwant: %s", got, want)
				}
			},
		},
		{
			Name: "enumerating posix groups",
			Check: func(t testing.TB) {
				out := doRunGetFirst(RD, "ldapsearch", "-LLL", "-H", "ldap://localhost:3893", "-D", env.svcdn, "-w", "mysecret", "-x", "-bdc=glauth,dc=com", "(objectclass=posixgroup)")
				if got, want := out, env.expectedgroup; got != want {
					t.Fatalf("should get a list starting with the 'superheros' group\ngot:  %s\nwant: %s", got, want)
				}
			},
		},
		{
			Name: "searching for members of the 'superheros' group",
			Check: func(t testing.TB) {
				out := doRunGetFirst(RD, "ldapsearch", "-LLL", "-H", "ldap://localhost:3893", "-D", env.svcdn, "-w", "mysecret", "-x", "-bdc=glauth,dc=com", "(memberOf=ou=superheros,ou=groups,dc=glauth,dc=com)")
				if got, want := out, env.expectedfirstaccount; got != want {
					t.Fatalf("should get a list starting with the 'hackers' user\ngot:  %s\nwant: %s", got, want)
				}
			},
		},
		{
			Name: "performing a complex search for members of 'superheros' group",
			Check: func(t testing.TB) {
				out := doRunGetFirst(RD, "ldapsearch", "-LLL", "-H", "ldap://localhost:3893", "-D", env.svcdn, "-w", "mysecret", "-x", "-bdc=glauth,dc=com", "(&(objectClass=*)(memberOf=ou=superheros,ou=groups,dc=glauth,dc=com))")
				if got, want := out, env.expectedfirstaccount; got != want {
					t.Fatalf("should get a list starting with the 'hackers' user\ngot:  %s\nwant: %s", got, want)
				}
			},
		},
		{
			Name: "searching for the 'hacker' user using a TOTP-enabled account",
			Check: func(t testing.TB) {
				if !env.checkTOTP {
					t.SkipNow()
				}
				otpvalue := doRunGetFirst(RD, "oathtool", "--totp", "-b", "-d", "6", "3hnvnk4ycv44glzigd6s25j4dougs3rk")
				out := doRunGetFirst(RD, "ldapsearch", "-LLL", "-H", "ldap://localhost:3893", "-D", env.otpdn, "-w", "mysecret"+otpvalue, "-x", "-bou=superheros,dc=glauth,dc=com", "cn=hackers")
				if got, want := out, env.scopedaccount; got != want {
					t.Fatalf("should find them in in the 'superheros' group\ngot:  %s\nwant: %s", got, want)
				}
			},
		},
		{
			Name: "searching for the 'hacker' user using a TOTP-enabled account and no value",
			Check: func(t testing.TB) {
				if !env.checkTOTP {
					t.SkipNow()
				}
				out := doRunGetFirst(RD, "ldapsearch", "-LLL", "-H", "ldap://localhost:3893", "-D", env.otpdn, "-w", "mysecret", "-x", "-bou=superheros,dc=glauth,dc=com", "cn=hackers")
				if got, want := out, "exit status 49"; got != want {
					t.Fatalf("should get 'Invalid credentials(49)'\ngot:  %s\nwant: %s", got, want)
				}
			},
		},
		{
			Name: "searching for the 'hacker' user using a TOTP-enabled account and the wrong value",
			Check: func(t testing.TB) {
				if !env.checkTOTP {
					t.SkipNow()
				}
				out := doRunGetFirst(RD, "ldapsearch", "-LLL", "-H", "ldap://localhost:3893", "-D", env.otpdn, "-w", "mysecret123456", "-x", "-bou=superheros,dc=glauth,dc=com", "cn=hackers")
				if got, want := out, "exit status 49"; got != want {
					t.Fatalf("should get 'Invalid credentials(49)'\ngot:  %s\nwant: %s", got, want)
				}
			},
		},
		{
			Name: "searching for the 'hacker' user",
			Check: func(t testing.TB) {
				if env.checkemployeetype == "" {
					t.SkipNow()
				}
				out := doRunGetSecond(RD, "ldapsearch", "-LLL", "-H", "ldap://localhost:3893", "-D", env.svcdn, "-w", "mysecret", "-x", "-bdc=glauth,dc=com", env.checkemployeetype, "employeetype")
				if got, want := out, "employeetype: Intern"; got != want {
					t.Fatalf("type should be 'Intern'\ngot:  %s\nwant: %s", got, want)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			tc.Check(t)
		})
	}
}

func TestSampleSimple(t *testing.T) {
	env := testEnv{
		checkanonymousrootDSE: true,
		checkTOTP:             true,
		checkbindUPN:          true,
		expectedinfo:          "supportedLDAPVersion: 3",
		svcdn:                 "cn=serviceuser,ou=svcaccts,dc=glauth,dc=com",
		svcdnnogroup:          "cn=serviceuser,dc=glauth,dc=com",
		otpdn:                 "cn=otpuser,ou=superheros,dc=glauth,dc=com",
		expectedaccount:       "dn: cn=hackers,ou=superheros,ou=users,dc=glauth,dc=com",
		scopedaccount:         "dn: cn=hackers,ou=superheros,dc=glauth,dc=com",
		expectedfirstaccount:  "dn: cn=hackers,ou=superheros,ou=users,dc=glauth,dc=com",
		expectedgroup:         "dn: ou=superheros,ou=users,dc=glauth,dc=com",
		checkemployeetype:     "cn=hackers",
	}

	svc := startSvc(SD, glauthBinary(), "-c", ldapOnlyConfig(t, "sample-simple.cfg"))
	batteryOfTests(t, &env)
	stopSvc(svc)
}

func TestSQLitePlugin(t *testing.T) {
	matchingLibrary := doRunGetFirst(RD, "ls", "bin/sqlite.so")
	if matchingLibrary != "bin/sqlite.so" {
		t.SkipNow()
	}

	env := testEnv{
		checkanonymousrootDSE: true,
		checkTOTP:             false,
		checkbindUPN:          true,
		expectedinfo:          "supportedLDAPVersion: 3",
		svcdn:                 "cn=serviceuser,ou=svcaccts,dc=glauth,dc=com",
		svcdnnogroup:          "cn=serviceuser,dc=glauth,dc=com",
		otpdn:                 "cn=otpuser,ou=superheros,dc=glauth,dc=com",
		expectedaccount:       "dn: cn=hackers,ou=superheros,ou=users,dc=glauth,dc=com",
		scopedaccount:         "dn: cn=hackers,ou=superheros,dc=glauth,dc=com",
		expectedfirstaccount:  "dn: cn=hackers,ou=superheros,ou=users,dc=glauth,dc=com",
		expectedgroup:         "dn: ou=superheros,ou=users,dc=glauth,dc=com",
		checkemployeetype:     "",
	}

	svc := startSvc(SD, glauthBinary(), "-c", "pkg/plugins/glauth-sqlite/sample-database.cfg")
	batteryOfTests(t, &env)
	stopSvc(svc)
}

func TestLdapInjection(t *testing.T) {
	matchingContainers := doRunGetFirst(RD, "sh", "-c", "docker ps | grep ldap-service | wc -l")
	if matchingContainers != "1" {
		t.SkipNow()
	}

	env := testEnv{
		checkanonymousrootDSE: false,
		checkTOTP:             true,
		checkbindUPN:          false,
		expectedinfo:          "objectClass: top",
		svcdn:                 "cn=serviceuser,cn=svcaccts,ou=users,dc=glauth,dc=com",
		svcdnnogroup:          "", // ignore
		otpdn:                 "cn=otpuser,cn=superheros,ou=users,dc=glauth,dc=com",
		expectedaccount:       "dn: cn=hackers,cn=superheros,ou=users,dc=glauth,dc=com",
		scopedaccount:         "dn: cn=hackers,cn=superheros,ou=users,dc=glauth,dc=com",
		expectedfirstaccount:  "dn: cn=johndoe,cn=superheros,ou=users,dc=glauth,dc=com",
		expectedgroup:         "dn: ou=superheros,ou=users,dc=glauth,dc=com",
		checkemployeetype:     "",
	}

	svc := startSvc(SD, glauthBinary(), "-c", "sample-ldap-injection.cfg")
	batteryOfTests(t, &env)
	stopSvc(svc)
}

// -----=============================================================================----

const SD = 3 // Start Delay
const RD = 2 // Response Delay

func startSvc(delay time.Duration, name string, arg ...string) *exec.Cmd {
	cmd := exec.Command(name, arg...)
	cmd.Start()
	if delay != 0 {
		time.Sleep(time.Second * delay)
	}
	return cmd
}

func stopSvc(svc *exec.Cmd) {
	svc.Process.Kill()
}

func doRunGetFirst(delay time.Duration, name string, arg ...string) string {
	out := strings.SplitN(doRun(delay, name, arg...), "\n", 2)
	if out == nil || len(out) < 1 {
		return "*fail*"
	}
	return out[0]
}

func doRunGetSecond(delay time.Duration, name string, arg ...string) string {
	out := strings.SplitN(doRun(delay, name, arg...), "\n", 3)
	if out == nil || len(out) < 2 {
		return "*fail*"
	}
	return out[1]
}

func doRun(delay time.Duration, name string, arg ...string) string {
	out, err := exec.Command(name, arg...).Output()
	if err != nil {
		return err.Error()
	}
	if delay != 0 {
		time.Sleep(time.Second * delay)
	}
	return strings.TrimSpace(string(out))
}
