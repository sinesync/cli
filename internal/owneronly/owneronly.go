// Package owneronly restricts a file to the account that owns it.
//
// This exists because os.Chmod does not mean the same thing everywhere. On unix
// 0600 is the whole answer. On Windows Go's Chmod toggles one bit — the
// read-only attribute — and has no effect on who may read the file, so code that
// asked for 0600 and checked the error got a world-readable file and no
// indication of it. Two of the files in this repo that did so hold key material.
//
// Restricting a file to its owner on Windows means writing a DACL: one entry
// granting the current user, and PROTECTED so the permissive entries the parent
// directory would otherwise pass down are dropped rather than merged.
//
// Both halves also provide IsOwnerOnly, because a test cannot assert this with
// os.Stat either — the mode bits Windows reports say nothing about the ACL.
package owneronly

// Apply restricts path to the current user: read and write for them, nothing
// for anyone else.
//
// It is not a substitute for creating the file privately in the first place.
// Between creation and this call the file exists under whatever the default
// grants, so callers that can create restricted should still do so; this closes
// the gap on the platform where creating restricted is not expressible through
// the os package.

// IsOwnerOnly reports whether path is readable only by its owner.
//
// Written for tests. It answers the question the assertion `Mode().Perm() ==
// 0600` was really asking, on both platforms, rather than one where that
// happens to be the same question.
