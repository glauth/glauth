# Changelog

## [2.3.2](https://github.com/glauth/glauth/compare/v2.3.1...v2.3.2) (2024-02-19)


### Bug Fixes

* remove spinlock in monitoring code ([#405](https://github.com/glauth/glauth/issues/405)) ([a2c151b](https://github.com/glauth/glauth/commit/a2c151b0d025332462369a846a51ef4deff5332b))

## [2.3.1](https://github.com/glauth/glauth/compare/v2.2.1...v2.3.1) (2024-02-12)


### Features

* allow tracing configuration via main config ([f692394](https://github.com/glauth/glauth/commit/f692394942aa0f93a1aa1572331fd1c3e3553156))
* introduce context for otlp spans into handler pkg ([d05630f](https://github.com/glauth/glauth/commit/d05630f66b80a776fd406782ad1fde5c6c66eac6))
* introduce context for otlp spans into plugins pkg ([46e49b6](https://github.com/glauth/glauth/commit/46e49b6976318a9f3670b88bdcb3411dfac0a17c))
* introduce otelsql ([2ca5312](https://github.com/glauth/glauth/commit/2ca53126965aa7d42b23aee15f750df12822d454))
* introduce otlp tracer ([0cf0403](https://github.com/glauth/glauth/commit/0cf04037a2a7b38c8ed7af2451b115f48c5427b5))
* wire up basic tracer ([1c2b23c](https://github.com/glauth/glauth/commit/1c2b23c00ff85b83a6d2e4bf4a9a68081aaf2777))


### Bug Fixes

* drop vendored toml ([24455e3](https://github.com/glauth/glauth/commit/24455e39889716ce7ae1e7e8a7dacfa7d4c96080))
* formatting ([c90cbfe](https://github.com/glauth/glauth/commit/c90cbfe5fb090fc19a55d64e01cd0e31c38bf2f0))
* go test not checking otp within allowed basedn ([#403](https://github.com/glauth/glauth/issues/403)) ([ed52a91](https://github.com/glauth/glauth/commit/ed52a91ec4117ff58fe606a1d8ba10786501a1e5))
* move all toml parsing into a new internal package, drop the mappings in favour of toml.Primitive decoding ([3ba8e11](https://github.com/glauth/glauth/commit/3ba8e1113217be647d240261322453d213ea7da4))
* removed config setup from main, reshoring log configuration ([5fe8aca](https://github.com/glauth/glauth/commit/5fe8aca852bdfe7e375ea99b87074bae35fc3407))
* update tracing code to work with breaking otlp 1.20 changes ([1a37396](https://github.com/glauth/glauth/commit/1a3739610997b58100040d0c8a405596fccc8e23))
* upgrade to use BurntSushi/toml ([f9addbc](https://github.com/glauth/glauth/commit/f9addbc2c5b13ccc2779dbabc4c55bc8706f53d6))


### Miscellaneous Chores

* release 2.3.1 ([0bf3d4a](https://github.com/glauth/glauth/commit/0bf3d4a82a8451e7bbda74e3730345aab5a855a7))

## [2.3.0](https://github.com/glauth/glauth/compare/v2.2.0...v2.3.0) (2023-10-02)


### ⚠ BREAKING CHANGES

* **plugins:** Rename the groups table to ldapgroups ([#326](https://github.com/glauth/glauth/issues/326))

### Features

* Update migration code to support table names ([#339](https://github.com/glauth/glauth/issues/339)) ([349431c](https://github.com/glauth/glauth/commit/349431c6caa0388d17ab987621eb9be5f019155e))


### Bug Fixes

* **plugins:** Rename the groups table to ldapgroups ([#326](https://github.com/glauth/glauth/issues/326)) ([675b236](https://github.com/glauth/glauth/commit/675b236328a21a65daa7876a1a3c6900b85b1964))


### Miscellaneous Chores

* release 2.3.0 ([0c11325](https://github.com/glauth/glauth/commit/0c11325a2482d5067c805a4c7ed948a5e337b8f8))
