
# plugins

## builder

- MODIFICATION: worker runtime retrieved from local source instead of an remote one without verification
    ref: const workerRuntimeUrl in client/plugos/plug_compile.ts
    ref: https://github.com/alvarolm/saferbullet/issues/1772
    
- MODIFICATION: compiled plugins are never minified, this change was made to keep them human readable in pro of transparency which is fundamental to security
  also:
    - most of cdn compress on the fly (where plugins are usually hosted, eg github cdn)
    - most connections download speeds make the transfer unnoticable
    - the extra storage is negligible for most of the users
    ref: https://community.silverbullet.md/t/strengthening-security/3746/5?u=alvarolm

## signing/verification

- NEW-FEATURE: simple plugin signing and verification
  
  components:
  
  - plug-signer: go command line utility for signing plugins
    ref: ./plug-signer/
  
  - signing lib: go package for signing operations (shared between plug-signer and server)
    ref: ./plug-signer/signing/
  
  - server-side verification: verifies plugin signature(s) against trusted keys, the trusted keys are stored in the protection config, which is retrieved from a TOML file specified by the SB_PROTECTION_CONFIG environment variable during server initialization.
    ref: ./server/protection.go,
    ref: ./server/protection_plugin.go,
    ref: ./server/protection_fs.go,
    ref: ./server/protection_plugin_test.go
  
  important notes:
  
  - Signature detection limit: Signatures are only searched for in the first 50 lines of a plugin file. This is a security measure to prevent DoS attacks from scanning arbitrarily large files. Signatures should always be placed at the top of the file (which is the default behavior of plug-signer).
  
  - Multi-signature support: A plugin can be signed by multiple keys. When re-signing with the same key, the old signature is replaced. When signing with a different key, the new signature is added while preserving existing signatures from other keys. Verification only requires **one** valid signature from a trusted key to pass.