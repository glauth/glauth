package version

import (
	"fmt"
	"runtime/debug"
)

type gitInfo struct {
	BuildTime string
	Commit    string
	Dirty     bool
}

// GetVersion reads builtime vars and returns a full string containing info about
// the currently running version of the software. Primarily used by the
// --version flag at runtime.
func GetVersion() string {

	// TODO @shipperizer see if it's worth replacing with info.Main.Path
	// aka github.com/glauth/glauth/v2 - not great but worth checking

	name := "GLauth"

	info, ok := debug.ReadBuildInfo()

	if !ok {
		return fmt.Sprintf(`
%s
Non-release build`,
			name)
	}

	gitInfo := vcsInfo(info.Settings)

	// If a release, use the tag
	if !gitInfo.Dirty {
		return fmt.Sprintf(`%s %s
Build time: %s
Commit: %s`, name, Version, gitInfo.BuildTime, gitInfo.Commit)
	}

	return fmt.Sprintf(`%s
Non-release build based on tag %s
Build time: %s
Commit: %s`, name, Version, gitInfo.BuildTime, gitInfo.Commit)

}

func vcsInfo(settings []debug.BuildSetting) *gitInfo {
	info := new(gitInfo)

	info.BuildTime = "unknown"
	info.Commit = "unknown"
	info.Dirty = false

	for _, v := range settings {
		switch v.Key {
		case "vcs.revision":
			info.Commit = v.Value
		case "vcs.modified":
			info.Dirty = v.Value == "true"
		case "vcs.time":
			info.BuildTime = v.Value
		}
	}

	return info
}
