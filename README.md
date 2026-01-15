![GitHub Repo stars](https://img.shields.io/github/stars/alvarolm/saferbullet)
![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/alvarolm/saferbullet/total)

> [!CAUTION]
> - Contributions, opinions or feedback of any kind are more than welcome and greatly appreciated!
> - Mind there is NO GUARANTEE WHATSOEVER for this software, use at your own risk.
> - This software has not been actively tested. It may contain unexpected behaviors

References:
- [SilverBullet](https://github.com/silverbulletmd/silverbullet)
- [Community discussion](https://community.silverbullet.md/t/strengthening-security/3746)

# SaferBullet

This is a fork of SilverBullet focused on improving security, its 100% compatible with SilverBullet and can be used as a drop-in replacement.

I will try to keep it updated with the latest version of SilverBullet.

I'm also evaluating the possibility of a "ready to deploy" binary that includes all the missing features to run SaferBullet in a production environment (tls, file system encryption, etc).

## Improvements

- [WIP] regular checks for vulnerabilities in dependencies
- [TODO] updated dependencies
- [TODO] saner defaults
- [WIP] elimination of unverified remote code loading
- plugin security:
  - [DONE] signing and verification of packaged plugins
  - [DONE] disable minification to ensure compiled code remains human-readable and auditable of packaged plugins
- server security:
  - [EVALUATING] file system encryption
  - [EVALUATING] automatic tls encryption and authentication
  - [TODO] proxy api request filtering (domain whitelisting)

see [saferbullet-changelog.md](./saferbullet-changelog.md) for the current implementation status

## LICENSE
MIT
[LICENSE.md](./LICENSE.md)
