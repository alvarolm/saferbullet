![GitHub Repo stars](https://img.shields.io/github/stars/alvarolm/saferbullet)
![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/alvarolm/saferbullet/total)

> [!CAUTION]
> - This code has not been actively tested. It may contain unexpected behaviors
> - Contributions, opinions or feedback of any kind are more than welcome and greatly appreciated!
> - This is an effort with NO GUARANTEE WHATSOEVER, use at your own risk.

References:
- [SilverBullet](https://github.com/silverbulletmd/silverbullet)
- [Community discussion](https://community.silverbullet.md/t/strengthening-security/3746)

# SaferBullet

This is a fork of SilverBullet focused on improving security, is 100% compatible with SilverBullet and can be used as a drop-in replacement.

I will try to keep it updated with the latest version of SilverBullet.

I'm also evaluating the possibility of a "ready to deploy" binary that includes all the missing features to run SaferBullet in a production environment (tls, file system encryption, etc).

## Improvements

- regular checks for vulnerabilities in dependencies [WIP]
- updated dependencies [TODO]
- saner defaults [TODO]
- elimination of unverified remote code loading [WIP]  
- plugin security:
  - signing and verification of packaged plugins [DONE]
  - disable minification to ensure compiled code remains human-readable and auditable of packaged plugins [DONE]
- server security:
  - file system encryption [EVALUATING]
  - automatic tls encryption and authentication [EVALUATING]
  - external communication protection, proxy api (domain whitelisting) [TODO]

see [saferbullet-changelog.md][saferbullet-changelog.md] for the current implementation status
