# Contributing to the Containers Rust Projects

We'd love to have you join the community! Below summarizes the processes
that we follow.

Note the containers org is a large github organization with many different people
working on all a lot of different tools and libraries. The steps listed here to not
universally apply to each repository. Please make sure to read the contributing
docs in each repository as they may do things differently.

This documented is primarily aimed at the following repositories:

- [netavark](https://github.com/containers/netavark)
- [aardvark](https://github.com/containers/aardvark-dns/)

However most of the things here listed are very generic and apply when contributing to most public projects

## Topics

* [Reporting Issues](#reporting-issues)
* [Submitting Pull Requests](#submitting-pull-requests)
* [Go Dependency updates](#go-dependency-updates)
* [Find bad changes with git bisect](#find-bad-changes-with-git-bisect)

## Reporting Issues

Before reporting an issue, check our backlog of Open Issues to see if someone else has already reported it.
If so, feel free to add your scenario, or additional information, to the discussion.
Or simply "subscribe" to it to be notified when it is updated.
Please do not add comments like "+1" or "I have this issue as well" without adding any new information.
Instead, please add a thumbs-up emoji to the original report.

Note: Older closed issues/PRs are automatically locked.
If you have a similar problem please open a new issue instead of commenting.

If you find a new issue with the project we'd love to hear about it!
The most important aspect of a bug report is that it includes enough information for us to reproduce it.
Please include as much detail as possible, including all requested fields in the template.
Not having all requested information makes it much harder to find and fix issues.
A reproducer is the best thing you can include.
Reproducers make finding and fixing issues much easier for maintainers.
The easier it is for us to reproduce a bug, the faster it'll be fixed!

Please don't include any private/sensitive information in your issue!
Security issues should NOT be reported via Github and should instead be reported via the process described [here](SECURITY.md).

## Submitting Pull Requests

No Pull Request (PR) is too small!
Typos, additional comments in the code, new test cases, bug fixes, new features, more documentation, ... it's all welcome!

Our projects follow the normal GitHub PR workflow for contributions.
If you never worked with GitHub and git before you likely first need to understand some basic about them.
The general work you have to do when you contribute the first time is something like this:
 - Fork the project on GitHub.
 - Clone that fork locally.
 - Create a new branch.
 - Make your change and commit it.
 - Push the branch to your fork.
 - Open a PR against the upstream repo.

You can find some easy tutorial online such as [this one](https://opensource.com/article/19/7/create-pull-request-github)
and check out the official [GitHub docs](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests)
that contain much more detail.

All development happens on the `main` branch so all PRs should be submitted against that branch.
Maintainers will take care of backporting if needed.

While bug fixes can first be identified via an "issue" in Github, that is not required.
It's ok to just open up a PR with the fix, but make sure you include the same information you would have included in an issue - like how to reproduce it.

PRs for new features should include some background on what use cases the new code is trying to address.
When possible and when it makes sense, try to break-up larger PRs into smaller ones - it's easier to review smaller code changes.
But only if those smaller ones make sense as stand-alone PRs.

Regardless of the type of PR, all PRs should include:
* Well-documented code changes, both through comments in the code itself and high-quality commit messages.
  A commit message should answer *why* a change was made.
* Additional tests. Ideally, they should fail without your code change applied. A test can be a unit test
  (which should be added in the same file as the code being tested) or in a more complex suite often found in the
  `test/` or `tests/` directory in each respective repo.
  Sometimes it may not be possible to add a useful test (e.g. a race condition that is very hard to trigger),
  in that case a maintainer can decide to merge without tests.
* Documentation updates to reflect the changes made in the pull request often found in the `docs/` directory.

Squash your commits into logical pieces of work that might want to be reviewed separate from the rest of the PRs.
Code changes, test and documentation updates should be part of the same commit as long as they are for the same
feature/bug fix. Dependency updates are best kept in an individual commit. Totally unrelated changes, i.e.
fixing typos in a different code part or adding a completely different feature should go into their own PR.
Often squashing down to just one commit is acceptable since in the end the entire PR will be reviewed anyway.
When in doubt, ask a maintainer how they prefer it.

When your PR fixes an issue, please note that by including `Fixes: #00000` in the commit description.
More details on this are below, in the "Describe your changes in Commit Messages" section.

This repository follows a two-ack policy for merges.
PRs will be approved by an approver listed in [`OWNERS`](OWNERS) file in the root of the repository.
They will then be merged by a repo owner. Two reviews are required for a pull request to merge.

### Describe your Changes in Commit Messages

Describe your problem.
Whether your patch is a one-line bug fix or 5000 lines of a new feature, there must be an underlying problem that motivated you to do this work.
Convince the reviewer that there is a problem worth fixing and that it makes sense for them to read past the first paragraph.

Describe user-visible impact.
Straight up crashes and lockups are pretty convincing, but not all bugs are that blatant.
Even if the problem was spotted during code review, describe the impact you think it can have on users.
Keep in mind that the majority of users run packages provided by distributions, so include anything that could help route your change downstream.

Quantify optimizations and trade-offs.
If you claim improvements in performance, memory consumption, stack footprint, or binary size, include
numbers that back them up.
But also describe non-obvious costs.
Optimizations usually aren’t free but trade-offs between CPU, memory, and readability; or, when it comes to heuristics, between different workloads.
Describe the expected downsides of your optimization so that the reviewer can weigh costs against
benefits.

Once the problem is established, describe what you are actually doing about it in technical detail.
It’s important to describe the change in plain English for the reviewer to verify that the code is behaving as you intend it to.

Solve only one problem per patch.
If your description starts to get long, that’s a sign that you probably need to split up your patch.

If the patch fixes a logged bug entry, refer to that bug entry by number and URL.
If the patch follows from a mailing list discussion, give a URL to the mailing list archive.
Please format these lines as `Fixes:` followed by the URL or, for Github bugs, the bug number preceded by a #.
For example:

```
Fixes: #00000
Fixes: https://github.com/containers/common/issues/00000
Fixes: https://issues.redhat.com/browse/RHEL-00000
Fixes: RHEL-00000
```

However, try to make your explanation understandable without external resources.
In addition to giving a URL to a mailing list archive or bug, summarize the relevant points of the discussion that led to the patch as submitted.

If you want to refer to a specific commit, don’t just refer to the SHA-1 ID of the commit.
Please also include the oneline summary of the commit, to make it easier for reviewers to know what it is about. If the commit was merged in Github, referring to a Github PR number is also a good option, as that will retain all discussion from development, and makes including a summary less critical.
Examples:

```
Commit f641c2d9384e ("fix bug in rm -fa parallel deletes") [...]
PR #00000
```

When referring to a commit by SHA, you should also be sure to use at least the first twelve characters of the SHA-1 ID.
The Podman repository holds a lot of objects, making collisions with shorter IDs a real possibility.
Bear in mind that, even if there is no collision with your six-character ID now, that condition may change five years from now.

The following git config settings can be used to add a pretty format for outputting the above style in the git log or git show commands:

```
[core]
        abbrev = 12
[pretty]
        fixes = Fixes: %h (\"%s\")
```

### Sign your PRs

The sign-off is a line at the end of the explanation for the patch. Your
signature certifies that you wrote the patch or otherwise have the right to pass
it on as an open-source patch. The rules are simple: if you can certify
the below (from [developercertificate.org](http://developercertificate.org/)):

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
660 York Street, Suite 102,
San Francisco, CA 94110 USA

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.

Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

Then you just add a line to every git commit message:

    Signed-off-by: Joe Smith <joe.smith@email.com>

Use a real name (sorry, no anonymous contributions).
A real name does not require a legal name, nor a birth name, nor any name that appears
on an official ID (e.g. a passport). Your real name is the name you convey to people in
the community for them to use to identify you as you. The key concern is that your
identification is sufficient enough to contact you if an issue were to arise in the
future about your contribution.

If you set your `user.name` and `user.email` git configs, you can sign your commit automatically with `git commit -s`.

### Code review

Once the PR is submitted a reviewer will take a look at. Should nobody respond to it
within 2 weeks please ping a maintainer, sometimes PRs are overlooked or forgotten.

Keep an eye out for the CI results on the PR. If all is well then all tasks should succeed, on some
repos the CI time can take several hours until the tests are finished. If something failed try to
take a look at the logs to see if that seems related to your change or not. Then try to fix your
code or the test depending on what you think is right. If you are unsure or think it is
unrelated ask a maintainer, some tests are flaky and pass on a re-run.

After the reviewer/maintainer took a look they either write a comment stating `LGTM` (looks good to me)
and approve the PR, in which case you do not need to do any further changes, or they write a comment
with review feedback that you should address. Note that most changes require two reviews so only the
second reviewer will actually merge the PR.

If changes were requested do them locally in your branch and the amend them into the commit from the PR,
you can use `git commit -a --amend` for that. This will add the current changes to the previous commit.
Please do not push extra commits that say things like "apply code review" or "fix x" where x is a bug
introduced in a commit from your PR. In that case always squash the change into the right commit to keep
the git history clean. Our projects merge the commits as is and will will not squash them on merge to
preserve the full original context.

### Rebasing

When you created a branch to work on the fix/feature it no longer will be updated with the latest changes
from the upstream `main` branch. In order to keep your branch up to date you should rebase.

In order to do so add the upstream repo as remote in git, i.e. for containers/common use:
```
$ git remote add upstream git@github.com:containers/common.git
```

Then fetch the latest changes there with
```
$ git fetch upstream
```

And assuming you are still in your fix/feature branch:
```
$ git rebase upstream/main
```

If the PR is open longer you may have to rebase. You must rebase when there is a merge conflict,
this means the lines that you changed were also changed after you created your branch and in this
case git does not know what the right change is. You will need to manually resolve it, check
[here](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/addressing-merge-conflicts/resolving-a-merge-conflict-using-the-command-line)
for more information on how to do this.

It is recommended to always rebase on a new push to ensure it is testing against the latest code.

## Rust Dependency updates

To automatically keep dependencies up to date we use the [renovate](https://github.com/renovatebot/renovate) bot.
The bot automatically opens new PRs with updates that should be merged by maintainers.

However sometimes, especially during development, it can be the case that you like to update a dependency.

To do this, you can either run `cargo update` (to update all dependencies) or change the version of the specific dependency you want to update in `Cargo.toml`.

Please run `make` after this to ensure the project still builds after your dependency updates.
It may be necessary to make code changes to address the updates dependencies.

Then commit the changes and open a PR. If you want to add other changes it is recommended to keep the
dependency updates in their own commit as this makes reviewing them much easier.

## Find bad changes with git bisect

git bisect is very powerful command in order to quickly find commits that caused a regression.

For example assume you did a Podman update and now something that used to work fine is no longer working,
this is called a regression. If the change was not intentional it may be hard to find out what caused it.
git bisect can help with that.

First you need to know the last working version and the the new version were is stopped working and you
should have a simple test for you behavior. Then run
```
$ git bisect start <bad version> <good version>
```

Now git will go through the commits between them via binary search to find the first bad commit.
You need to compile the binary, then do your test and see if this works or not then use
```
$ git bisect good
```
if is is working or if it is not working:

```
$ git bisect bad
```

Then again compile and test and repeat the steps until git found only one commit left, this
should be the first bad commit. If you file an issue this information is very useful to us
developers to quickly see the root cause.

Given this can be a long manual process you can automate the bisect run if you have a good reproducer.
For example lets assume there is regression with `podman run $IMAGE someCommand` where it fails to
run and throws and error.
You can automate this after the bisect start command to give the good and bad version by using
```
$ git bisect run sh -c "make podman && bin/podman run $IMAGE someCommand || exit 1"
```
This will run the given command there for each command git steps through and if the command returns 0 it
assumes good version otherwise a bad version. `make podman` here is required to recompile podman each
time we are at a new commit. This is important as it would not test the correct binary for the given
commit otherwise leading to very wrong results. Then after this run your test of choice. You can also
pass complex scripts or commands as long as the exit code is 0 for the good case and > 0 for the bad
one it will work.

Note git bisect is not perfect sometimes it will fail to find a bad commit. This can have many reason
but a common is that the problem is not podman but rather some external dependency, can be a a dynamically
linked c lib, some external program podman calls or even the kernel. In these cases pin pointing the cause
will be more difficult.

There is much more useful information in the [git documentation](https://git-scm.com/docs/git-bisect) about this.
