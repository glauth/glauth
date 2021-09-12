Thank you for making a pull request!

A few things to be aware of as you're working on your PR:

## WIP Tag
Incomplete PRs are more than welcome - it can be useful to collaborate before 
implementation of an idea is complete. However, if your PR is not ready 
for merge, please add [WIP] to the end of the title (work-in-progress).

## Tests
Before committing, you are encouraged to run the small but growing test 
suite. This is accomplished by `make test`. Additionally, if you are adding
new functionality, consider adding tests covering your feature.

## CI
Each push to a branch connected to a PR will be run through GLAuth's 
CI system. Please use these to your advantage. In particular, the Github Actions 
integration tests rely on the LDAP queries returning with a set result, 
so if your changes will change the output, CI will likely fail.

To update, run `make fast && make updatetest && make test`. This will 
delete the output snapshots provided and make new ones. You can then 
inspect the changes and commit them.

Similarly, check codeclimate and try to fix what you find there if it fails.
