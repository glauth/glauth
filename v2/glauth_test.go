package main

import (
	"os"
	"os/exec"
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

func TestProperBuild(t *testing.T) {
	info, err := os.Stat("bin/glauth")
	if err != nil {
		t.Error(err)
	}
	mode := uint32(info.Mode())
	if mode&0b001001001 == 0 {
		t.Fatalf("bad file mode: %b", mode)
	}
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

	svc := startSvc(SD, "bin/glauth", "-c", "sample-simple.cfg")
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

	svc := startSvc(SD, "bin/glauth", "-c", "pkg/plugins/glauth-sqlite/sample-database.cfg")
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

	svc := startSvc(SD, "bin/glauth", "-c", "sample-ldap-injection.cfg")
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
