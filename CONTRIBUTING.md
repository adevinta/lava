# Contributing

**This project is in an early stage, we are not accepting external
contributions yet.**

## Workflow

The recommended workflow is feature branching.
That means that new features are developed in branches that are merged
to main once they are tested, reviewed and considered stable.

Small, short-lived and self-contained feature branches along with
small pull requests are recommended.
Feature flags are helpful to avoid having very long lived branches
that can be sometimes hard to merge, depending on how quickly the main
branch is updated.

The main branch of this repository is protected.
No one is allowed to push directly to main.

## Commit messages

Commit messages in this project follow a specific set of conventions,
which we discuss in this section.

```
Header line: explain the commit in one line (use the imperative)

Body of commit message is a few lines of text, explaining things
in more detail, possibly giving some background about the issue
being fixed, etc.

The body of the commit message can be several paragraphs, and
please do proper word-wrap and keep columns shorter than about
74 characters or so. That way "git log" will show things
nicely even when it's indented.

Make sure you explain your solution and why you're doing what you're
doing, as opposed to describing what you're doing. Reviewers and your
future self can read the patch, but might not understand why a
particular solution was implemented.
```

The header line of the commit must be prefixed by the primary affected
component followed by colon.

The body of the commit can be omitted if the header line describes the
change well enough and the pull request message contains the missing
details.

## Pull requests

Similarly to what happens with commit messages, pull requests follow a
specific set of conventions.

The title must explain the pull request in one line (use the
imperative) and must be prefixed by the primary affected component
followed by colon.

The body of the pull request is a few lines of text, explaining things
in more detail, possibly giving some background about the issue being
fixed, etc.

Make sure you explain your solution and why you're doing what you're
doing, as opposed to describing what you're doing.
Reviewers and your future self can read the patch, but might not
understand why a particular solution was implemented.

Pull requests must be in a "mergeable" state, pass all the automatic
checks and receive at least +1 from the reviewers before being merged.

When merging pull requests, using merge commits is mandatory.
That means that the commit history of the pull request must be
meaningful and clean.
