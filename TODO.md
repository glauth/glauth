# Todo before merging this branch

 * Handle git tags
 * Handle travis pipeline#
 * Hide or change version number if not a final tag - in other words, handle release vs nonrelease builds
   * I believe this will resolve it:
   * git tag -l --points-at HEAD
 * Perhaps also work on travis binary release
 * Add integration test for linux 32 bit binary (switch integration test to accept binary name as a param)
 * Fix travis-ci git clean issue (shows as unclean/0 when it's actually clean/1)
 * Add note somewhere (docs?) about how non linux64/32 binaries are not fully tested

 * Perhaps look at mac testing on travis for releases? This might be overkill
