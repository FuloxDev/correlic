# Homebrew formula for the macOS agent

`correlic-agent.rb` builds `correlic-agent` and `correlic-hook` from source
with the Go toolchain Homebrew installs as a build dependency. It is a
head-only formula for now (see the comment at the top of the file for why
and how to add a stable block with the next release).

## Install from a checkout

```sh
brew install --HEAD ./install/homebrew/correlic-agent.rb
brew upgrade --fetch-HEAD correlic-agent      # rebuild from the latest main
```

Then follow the caveats Homebrew prints (`brew info correlic-agent` shows
them again): configuration in `$(brew --prefix)/etc/correlic/`, root, Full
Disk Access, `sudo brew services start correlic-agent`.

## Turning it into a tap

So that `brew install fuloxdev/correlic/correlic-agent` works without a
checkout:

1. Create a repository named `homebrew-correlic` under the `FuloxDev` GitHub
   organisation (Homebrew maps `fuloxdev/correlic` to it).
2. Copy this file to `Formula/correlic-agent.rb` in that repository.
3. With each release, add a stable block (`url` of the tag's source tarball
   and its `sha256`) and run `brew audit --strict --online correlic-agent`
   and `brew test correlic-agent`.
4. Users then run `brew tap fuloxdev/correlic && brew install correlic-agent`
   (or `--HEAD` for the main branch).

A GitHub Actions workflow in that repository can bump the version and
checksum automatically on release (`brew bump-formula-pr` style), which is
the usual way to keep a tap current.
