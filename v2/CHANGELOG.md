# Changelog

## [2.2.2](https://github.com/glauth/glauth/compare/v2.2.1...v2.2.2) (2023-12-10)


### Bug Fixes

* drop vendored toml ([24455e3](https://github.com/glauth/glauth/commit/24455e39889716ce7ae1e7e8a7dacfa7d4c96080))
* formatting ([c90cbfe](https://github.com/glauth/glauth/commit/c90cbfe5fb090fc19a55d64e01cd0e31c38bf2f0))
* move all toml parsing into a new internal package, drop the mappings in favour of toml.Primitive decoding ([3ba8e11](https://github.com/glauth/glauth/commit/3ba8e1113217be647d240261322453d213ea7da4))
* removed config setup from main, reshoring log configuration ([5fe8aca](https://github.com/glauth/glauth/commit/5fe8aca852bdfe7e375ea99b87074bae35fc3407))
* upgrade to use BurntSushi/toml ([f9addbc](https://github.com/glauth/glauth/commit/f9addbc2c5b13ccc2779dbabc4c55bc8706f53d6))

## [2.3.0](https://github.com/glauth/glauth/compare/v2.2.0...v2.3.0) (2023-10-02)


### ⚠ BREAKING CHANGES

* **plugins:** Rename the groups table to ldapgroups ([#326](https://github.com/glauth/glauth/issues/326))

### Features

* Update migration code to support table names ([#339](https://github.com/glauth/glauth/issues/339)) ([349431c](https://github.com/glauth/glauth/commit/349431c6caa0388d17ab987621eb9be5f019155e))


### Bug Fixes

* **plugins:** Rename the groups table to ldapgroups ([#326](https://github.com/glauth/glauth/issues/326)) ([675b236](https://github.com/glauth/glauth/commit/675b236328a21a65daa7876a1a3c6900b85b1964))


### Miscellaneous Chores

* release 2.3.0 ([0c11325](https://github.com/glauth/glauth/commit/0c11325a2482d5067c805a4c7ed948a5e337b8f8))
