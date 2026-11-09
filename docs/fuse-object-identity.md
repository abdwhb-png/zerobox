# Guarded FUSE descriptor metadata

The guarded filesystem gives each looked-up object a synthetic FUSE inode and pins its backing object with a close-on-exec descriptor. Metadata comes from a fresh `fstat` on that descriptor, including when Linux sends `getattr` without a file handle. Replacing, renaming or unlinking a pathname therefore cannot make an existing descriptor report the replacement's attributes.

## Identity and lifetime

Lookup checks the current object before recording a kernel reference. A different device/inode identity or a different resolved dentry receives a new synthetic inode; the old inode remains available to existing references. Dentry comparison matters when a host recreates a pathname as a hardlink to the same disk inode. Those names must retain their separate policy checks.

Each successful entry or create reply owns one lookup reference. FUSE `forget`, including batched forget requests, releases those references. Open file handles retain the same inode until release. When neither reference remains, ZeroBox drops the pinned descriptor and removes only that inode's namespace mapping. Plain directory listings do not pin descriptors for every listed entry. Unmount drops all remaining state.

File opens reopen the pinned object through ZeroBox's own procfs descriptor rather than looking up its old pathname. Policy checks run before and after reopening; the state mutex is released before potentially blocking opens. A pinned symlink is rejected, so stripping `O_NOFOLLOW` from this internal procfs reopen does not allow an application to follow a symlink it prohibited.

## Policy and resource boundaries

Each metadata operation checks the logical path and the freshly resolved descriptor destination. Moving an open file to a denied name therefore makes its metadata inaccessible, even if an allowed replacement occupies its former pathname. Linux appends ` (deleted)` to unlinked descriptor paths; both the raw spelling and the spelling without that suffix are checked. Because procfs does not disambiguate that marker from a literal filename, a literal name ending in that suffix can also be denied if its stripped spelling is protected.

Pinned descriptors preserve identity only. Attributes, symlink targets and destination policy checks remain live; entry and attribute TTLs remain zero. Structural traversal directories still expose synthetic attributes, and arbitrary Unix sockets remain denied.

Before mounting a guarded view, ZeroBox raises its process's soft `RLIMIT_NOFILE` to its existing hard limit. A scan of more than 4,000 paths otherwise exhausts a common 4,096-descriptor soft limit. The hard limit and persistent machine configuration are unchanged. Failure to read or raise the limit aborts preparation with an explicit error. The hard limit remains the finite resource ceiling; this design retains one descriptor per live looked-up inode, plus open handles and mount overhead.

## Validation and scope

Mounted regressions cover external replacement/unlink, FUSE rename-overwrite/unlink, fresh size changes, denied renames before and after deletion, `O_PATH` files/directories, symlink descriptors, `O_NOFOLLOW`, and recreated hardlink aliases. Ownership tests cover partial forget, open-handle retention and cleanup without deleting a replacement's mapping. An isolated child process starts with a soft limit of 256, checks 6,000 distinct mounted files and verifies that unmount releases its descriptors while preserving the hard limit.

Run focused coverage with `cargo test --offline --locked -p zerobox --lib dynamic_fs::tests`. This correctness change does not establish a performance gain or qualify a new daily Pi runtime. Other pathname-based mutations and directory stream operations are not redesigned by this change.
