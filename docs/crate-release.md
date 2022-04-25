# Crate Release

The [`dragonball-sandbox`](https://github.com/openanolis/dragonball-sandbox) repository hosts a cargo workspace,
which contains multiple Rust library crates for developing VMM/secure-sandboxes. There are three types of scenarios
to publish crates from this repository to [crates.io](https://crates.io/):
1. [Initial Release](#initial-release)
2. [Regular Release](#regular-release)
3. [Patch Release](#patch-release)

## Initial Release

Special treatments are needed to publish crates from a workspace.

First, you need to prepare `README.md`, `CHANGELOG.md` and license files for each crate under the root directory of the
crate. These files have to be part of the crate so that they will be included when packaging the crate for publishing.

Second, the order in which the crates from a workspace are released is also important. Before publishing a crate,
all its dependent crates must be published first. The first ones that have to be published are the ones that have
no dependencies on crates from the same workspace. For example, the `dbs-interrupt` crate depends on `dbs-device`,
so `dbs-device` has to be published first. It is not allowed to publish a crate that has a `path` only dependency,
more details [here](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#multiple-locations).
After the dependency crates are released, the version of these crates has to be updated in the `Cargo.toml` files
of the crates that depend on them.

For the particular example of the `dbs-interrupt`, after that you have released `dbs-device` with 0.x.0 version,
you have to update this dependency in the `Cargo.toml` of `dbs-interrupt`, i.e.:

`dbs-device = { version = "=0.x.0", path = "../dbs-device" }`

Then, `dbs-interrupt` can be published as well by following the steps.

1. Create a separate `CHANGELOG.md`, if it doesn't already exist, in the root of the crate. The first paragraph should 
   be titled with the version of the new release and followed by subparagraphs detailing what's added, changed and fixed.
   Example for releasing v1.2.0:

```md
# v1.2.0

## Added

- New amazing API for doing all the work.

## Changed

- Magic parameter type is now `u64`.

## Fixed

- Fixed #42, the worst bug ever.

# v1.1.0
...
```

2. For the README, either create a separate one with information about that particular crate, or add a symlink
   to the `README.md` file from the root of the workspace. To create such symlink, use the following command:

```bash
ln <path_to_the_root_of_the_repository>/README \
<path_to_the_root_of_the_crate>/README
```

*Example:*

```bash
ln /dragonball-sandbox/README.md /dragonball-sandbox/crates/dbs-interrupt/README.md
```

3. The license files should have a symlink as well. For that, run the following commands:

```bash
ln <path_to_the_root_of_the_repository>/LICENSE-APACHE \
<path_to_the_root_of_the_crate>/LICENSE-APACHE
ln <path_to_the_root_of_the_repository>/LICENSE-BSD-3-Clause \
<path_to_the_root_of_the_crate>/LICENSE-BSD-3-Clause
```

4. If the crate has a `path` dependency, update that dependency in `Cargo.toml` with a `version` that is published
   on crates.io as explained in the introduction. This version should be the latest one released.

5. Update the version field in the `Cargo.toml` from the root of the particular crate.

6. Commit the symlinks together with the `Cargo.toml` and `CHANGELOG.md` updates.

7. To double-check what's being published, do a dry run first and fix warnings and errors.
   NOTE: Running this command requires closing the crates repository mirror. See
   [Cannot publish crates with crates repository mirrored](https://github.com/rust-lang/crates.io/issues/2249) for details.

```bash
cargo publish --dry-run
```
   Checklist:

   * crates.io has a maximum of 5 keywords. Each keyword must be ASCII text, start with a letter,
     and only contain letters, numbers, _ or -, and have at most 20 characters.
   * crates.io requires the description to be set.
   * crates.io requires either license or license-file to be set.

8. Once the pull request is merged, create a tag. Use the new version's changelog section for the tag text.
   Don't forget to remove the #s here, otherwise those lines won't appear in the tag message. The tag message here
   is not the release message. in the next step we will set the release message.

   Example for releasing v1.2.0:

```bash
git tag -a dbs-interrupt-v1.2.0
# Write the tag body (example below) and exit the editor
v1.2.0

Added

- New amazing API for doing all the work.

Changed

- Magic parameter type is now `u64`.

Fixed

- Fixed #42, the worst bug ever.
```

9. Push the tag to the upstream repository: `git push upstream --tags`. In this example, the upstream remote points
   to the original repository (not your fork).

10. Create as GitHub release. Go to the Releases page in the crate's repository and click Draft a new release
   (button on the right). In Tag version, pick the newly pushed tag. In Release title, write the tag name including v
    (example: dbs-interrupt-v1.2.3). The description should be the new version's changelog section. Click Publish release.

11. Publish the new version to crates.io. Make sure your HEAD is on the release tag,
    and you run the following commands from the root of the crate, and not of
    the workspace.

```bash
cargo publish
```

12. Add Dragonball administrator team as the owner of the new crate.

```bash
cargo owner --add github:openanolis:dragonball
cargo owner --add codeowner-github-handle
```

//////////////////////////////////////////////////
## Regular Release

1. Prepare any last-minute changes in a pull request, if necessary.
2. Update the `CHANGELOG.md` file in the subdirectory of the crate.
3. Update the version field in Cargo.toml in the root of the crate's repository.
4. Add a commit with the changelog and toml updates in the release pull request.
5. Follow the steps 7-10 of [Initial Release](#initial-release)

## Patch Release

:memo: Patch releases differ because they're not created off the
upstream main branch, but instead started off a stable release, and published
from a different, dedicated branch.

1. Checkout the tag you're starting from and create a new upstream branch. In
   the snippet below, the upstream remote points to the original repository,
   and the origin remote to your fork.
   Example setup for v1.2.1, which will be v1.2.0 plus a fix:

```bash
git checkout v1.2.0
git checkout -b v1.2.1_release
git push upstream v1.2.1_release # Push the upstream branch.
 # Create a local branch. This is what you'll be working on.
git checkout -b local_v1.2.1_release
# The development branch will sit in your fork.
git push -u origin local_v1.2.1_release
```

2. Follow the steps 2-5 from the [Regular Release process](#regular-release).
   **Pay attention to the branch against which you open the PR**. PRs need to be
   open against the vX.Y.Z_release branch (v1.2.1_release in the example
   above).
