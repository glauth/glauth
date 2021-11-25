package main

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
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

func TestIntegerStuff(t *testing.T) {

	Convey("Testing sample-simple local file-based LDAP server", t, func() {
		svc := startSvc(SD, "bin/glauth", "-c", "sample-simple.cfg")
		batteryOfTests(
			t,
			svc, testEnv{
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
			})
		stopSvc(svc)
	})

	matchingLibrary := doRunGetFirst(RD, "ls", "bin/sqlite.so")
	if matchingLibrary == "bin/sqlite.so" {
		Convey("Testing sample-database LDAP server", t, func() {
			svc := startSvc(SD, "bin/glauth", "-c", "pkg/plugins/sample-database.cfg")
			batteryOfTests(
				t,
				svc, testEnv{
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
				})
			stopSvc(svc)
		})
	}

	matchingContainers := doRunGetFirst(RD, "sh", "-c", "docker ps | grep openldap-service | wc -l")
	if matchingContainers == "1" {
		Convey("Testing sample-simple local LDAP server", t, func() {
			svc := startSvc(SD, "bin/glauth", "-c", "sample-ldap-injection.cfg")
			batteryOfTests(
				t,
				svc, testEnv{
					checkanonymousrootDSE: false,
					checkTOTP:             true,
					checkbindUPN:          false,
					expectedinfo:          "objectClass: top",
					svcdn:                 "cn=serviceuser,cn=svcaccts,ou=users,dc=glauth,dc=com",
					svcdnnogroup:          "", // ignore
					otpdn:                 "cn=otpuser,cn=superheros,ou=users,dc=glauth,dc=com",
					expectedaccount:       "dn: cn=hackers,cn=superheros,ou=users,dc=glauth,dc=com",
					scopedaccount:         "dn: cn=hackers,cn=superheros,dc=glauth,dc=com",
					expectedfirstaccount:  "dn: cn=johndoe,cn=superheros,ou=users,dc=glauth,dc=com",
					expectedgroup:         "dn: ou=superheros,ou=users,dc=glauth,dc=com",
					checkemployeetype:     "",
				})
			stopSvc(svc)
		})
	}
}

func batteryOfTests(t *testing.T, svc *exec.Cmd, env testEnv) {
	Convey("When searching for the 'hackers' user", func() {
		out := doRunGetFirst(RD, "ldapsearch", "-LLL", "-H", "ldap://localhost:3893", "-D", env.svcdn, "-w", "mysecret", "-x", "-bdc=glauth,dc=com", "cn=hackers")
		Convey("We should find them in the 'superheros' group", func() {
			So(out, ShouldEqual, env.expectedaccount)
		})
	})

	if env.svcdnnogroup != "" {
		Convey("When searching for the 'hackers' user without binding with a group", func() {
			out := doRunGetFirst(RD, "ldapsearch", "-LLL", "-H", "ldap://localhost:3893", "-D", env.svcdnnogroup, "-w", "mysecret", "-x", "-bdc=glauth,dc=com", "cn=hackers")
			Convey("We should find them in the 'superheros' group", func() {
				So(out, ShouldEqual, env.expectedaccount)
			})
		})
	}

	if env.checkbindUPN {
		Convey("When searching for the 'hackers' user after binding using the account's UPN", func() {
			out := doRunGetFirst(RD, "ldapsearch", "-LLL", "-H", "ldap://localhost:3893", "-D", "serviceuser@example.com", "-w", "mysecret", "-x", "-bdc=glauth,dc=com", "cn=hackers")
			Convey("We should find them in the 'superheros' group", func() {
				So(out, ShouldEqual, env.expectedaccount)
			})
		})
	}

	Convey("When querying the root SDE", func() {
		out := doRunGetSecond(RD, "ldapsearch", "-LLL", "-H", "ldap://localhost:3893", "-D", env.svcdn, "-w", "mysecret", "-x", "-s", "base", "(objectclass=*)")
		Convey("We should get some meta information", func() {
			So(out, ShouldEqual, env.expectedinfo)
		})
	})

	if env.checkanonymousrootDSE {
		Convey("When querying the root SDE anonymously without authorizing in config file", func() {
			out := doRunGetFirst(RD, "ldapsearch", "-LLL", "-H", "ldap://localhost:3893", "-x", "-s", "base", "(objectclass=*)")
			Convey("We should get error 50", func() {
				So(out, ShouldEqual, "exit status 50")
			})
		})
	}

	Convey("When enumerating posix groups", func() {
		out := doRunGetFirst(RD, "ldapsearch", "-LLL", "-H", "ldap://localhost:3893", "-D", env.svcdn, "-w", "mysecret", "-x", "-bdc=glauth,dc=com", "(objectclass=posixgroup)")
		Convey("We should get a list starting with the 'superheros' group", func() {
			So(out, ShouldEqual, env.expectedgroup)
		})
	})

	Convey("When searching for members of the 'superheros' group", func() {
		out := doRunGetFirst(RD, "ldapsearch", "-LLL", "-H", "ldap://localhost:3893", "-D", env.svcdn, "-w", "mysecret", "-x", "-bdc=glauth,dc=com", "(memberOf=ou=superheros,ou=groups,dc=glauth,dc=com)")
		Convey("We should get a list starting with the 'hackers' user", func() {
			So(out, ShouldEqual, env.expectedfirstaccount)
		})
	})

	Convey("When performing a complex search for members of 'superheros' group", func() {
		out := doRunGetFirst(RD, "ldapsearch", "-LLL", "-H", "ldap://localhost:3893", "-D", env.svcdn, "-w", "mysecret", "-x", "-bdc=glauth,dc=com", "(&(objectClass=*)(memberOf=ou=superheros,ou=groups,dc=glauth,dc=com))")
		Convey("We should get a list starting with the 'hackers' user", func() {
			So(out, ShouldEqual, env.expectedfirstaccount)
		})
	})

	if env.checkTOTP {
		Convey("When searching for the 'hacker' user using a TOTP-enabled account", func() {
			otpvalue := doRunGetFirst(RD, "oathtool", "--totp", "-b", "-d", "6", "3hnvnk4ycv44glzigd6s25j4dougs3rk")
			out := doRunGetFirst(RD, "ldapsearch", "-LLL", "-H", "ldap://localhost:3893", "-D", env.otpdn, "-w", "mysecret"+otpvalue, "-x", "-bou=superheros,dc=glauth,dc=com", "cn=hackers")
			Convey("We should find them in in the 'superheros' group", func() {
				So(out, ShouldEqual, env.scopedaccount)
			})
		})

		Convey("When searching for the 'hacker' user using a TOTP-enabled account and no value", func() {
			out := doRunGetFirst(RD, "ldapsearch", "-LLL", "-H", "ldap://localhost:3893", "-D", env.otpdn, "-w", "mysecret", "-x", "-bou=superheros,dc=glauth,dc=com", "cn=hackers")
			Convey("We should get 'Invalid credentials(49)'", func() {
				So(out, ShouldEqual, "exit status 49")
			})
		})

		Convey("When searching for the 'hacker' user using a TOTP-enabled account and the wrong value", func() {
			out := doRunGetFirst(RD, "ldapsearch", "-LLL", "-H", "ldap://localhost:3893", "-D", env.otpdn, "-w", "mysecret123456", "-x", "-bou=superheros,dc=glauth,dc=com", "cn=hackers")
			Convey("We should get 'Invalid credentials(49)'", func() {
				So(out, ShouldEqual, "exit status 49")
			})
		})
	}

	if env.checkemployeetype != "" {
		Convey("When searching for the 'hacker' user", func() {
			out := doRunGetSecond(RD, "ldapsearch", "-LLL", "-H", "ldap://localhost:3893", "-D", env.svcdn, "-w", "mysecret", "-x", "-bdc=glauth,dc=com", env.checkemployeetype, "employeetype")
			Convey("Employee type should be 'Intern'", func() {
				So(out, ShouldEqual, "employeetype: Intern")
			})
		})
	}

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
