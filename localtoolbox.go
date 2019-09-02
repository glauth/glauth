package main

import (
	"fmt"
	"github.com/nmcclain/ldap"
)

type localToolbox struct {
	cfg *config
}

type LocalBackend interface {
	getGroupName(gid int) string
	getGroupDNs(gids []int) []string
	getGroupMembers(gid int) []string
	getGroupMemberIDs(gid int) []string
}

func newLocalToolbox(cfg *config) *localToolbox {
	toolbox := localToolbox{cfg: cfg}
	return &toolbox
}

func (t localToolbox) getGroup(h LocalBackend, g configGroup) *ldap.Entry {
	attrs := []*ldap.EntryAttribute{}
	attrs = append(attrs, &ldap.EntryAttribute{"cn", []string{g.Name}})
	attrs = append(attrs, &ldap.EntryAttribute{"description", []string{fmt.Sprintf("%s via LDAP", g.Name)}})
	attrs = append(attrs, &ldap.EntryAttribute{"gidNumber", []string{fmt.Sprintf("%d", g.UnixID)}})
	attrs = append(attrs, &ldap.EntryAttribute{"objectClass", []string{"posixGroup"}})
	attrs = append(attrs, &ldap.EntryAttribute{"uniqueMember", h.getGroupMembers(g.UnixID)})
	attrs = append(attrs, &ldap.EntryAttribute{"memberUid", h.getGroupMemberIDs(g.UnixID)})
	dn := fmt.Sprintf("cn=%s,ou=groups,%s", g.Name, t.cfg.Backend.BaseDN)
	return &ldap.Entry{dn, attrs}
}

func (t localToolbox) getAccount(h LocalBackend, u configUser) *ldap.Entry {
	attrs := []*ldap.EntryAttribute{}
	attrs = append(attrs, &ldap.EntryAttribute{"cn", []string{u.Name}})
	attrs = append(attrs, &ldap.EntryAttribute{"uid", []string{u.Name}})

	if len(u.GivenName) > 0 {
		attrs = append(attrs, &ldap.EntryAttribute{"givenName", []string{u.GivenName}})
	}

	if len(u.SN) > 0 {
		attrs = append(attrs, &ldap.EntryAttribute{"sn", []string{u.SN}})
	}

	attrs = append(attrs, &ldap.EntryAttribute{"ou", []string{h.getGroupName(u.PrimaryGroup)}})
	attrs = append(attrs, &ldap.EntryAttribute{"uidNumber", []string{fmt.Sprintf("%d", u.UnixID)}})

	if u.Disabled {
		attrs = append(attrs, &ldap.EntryAttribute{"accountStatus", []string{"inactive"}})
	} else {
		attrs = append(attrs, &ldap.EntryAttribute{"accountStatus", []string{"active"}})
	}

	if len(u.Mail) > 0 {
		attrs = append(attrs, &ldap.EntryAttribute{"mail", []string{u.Mail}})
	}

	attrs = append(attrs, &ldap.EntryAttribute{"objectClass", []string{"posixAccount"}})

	if len(u.LoginShell) > 0 {
		attrs = append(attrs, &ldap.EntryAttribute{"loginShell", []string{u.LoginShell}})
	} else {
		attrs = append(attrs, &ldap.EntryAttribute{"loginShell", []string{"/bin/bash"}})
	}

	if len(u.Homedir) > 0 {
		attrs = append(attrs, &ldap.EntryAttribute{"homeDirectory", []string{u.Homedir}})
	} else {
		attrs = append(attrs, &ldap.EntryAttribute{"homeDirectory", []string{"/home/" + u.Name}})
	}

	attrs = append(attrs, &ldap.EntryAttribute{"description", []string{fmt.Sprintf("%s via LDAP", u.Name)}})
	attrs = append(attrs, &ldap.EntryAttribute{"gecos", []string{fmt.Sprintf("%s via LDAP", u.Name)}})
	attrs = append(attrs, &ldap.EntryAttribute{"gidNumber", []string{fmt.Sprintf("%d", u.PrimaryGroup)}})
	attrs = append(attrs, &ldap.EntryAttribute{"memberOf", h.getGroupDNs(append(u.OtherGroups, u.PrimaryGroup))})
	if len(u.SSHKeys) > 0 {
		attrs = append(attrs, &ldap.EntryAttribute{"sshPublicKey", u.SSHKeys})
	}
	dn := fmt.Sprintf("cn=%s,ou=%s,%s", u.Name, h.getGroupName(u.PrimaryGroup), t.cfg.Backend.BaseDN)
	return &ldap.Entry{dn, attrs}
}
