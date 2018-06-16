package main

// Just the beginning of testing - more to be added

import (
	"testing"
)

func TestGetVersionString(t *testing.T) {

	// Setup config and check output
	LastGitTag = "7"
	BuildTime = "20180616_042045Z"
	GitCommit = "a9837f3112fc049fd1e9faca6f56d8be1bec91bd"
	GitClean = "1"
	GitBranch = "dev"
	GitTagIsCommit = "0"

	versionOutput := getVersionString()
	if versionOutput != "7" {
		t.Errorf("Finish writing this test, output was: %s", versionOutput)
	}

	// TODO: write these cases

	// Cases to test:
	//    1) if GitTagIsCommit=1 - check for release-based strings (this build is release)
	//    2) if GitClean=1 - check for "Commit: " as well as value of commit str
	//    3) if GitClean=0 - Ensure "Commit: " is NOT there, as well ensure value of commit str is not there
	//    4) do additional checks for release behavior, as well as branch name

}
