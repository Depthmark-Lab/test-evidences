# Trusted public keys

The public keys `evidence/cli.py verify` accepts signatures from, one file per key version, named by the key id the signer writes in each envelope: `evd-<family>-lab-v<version>.pub.pem`.

The private keys stay in Vault Transit and cannot be exported. The homelab script that creates the keys also writes these files:

```
~/code/alexandreodelisle/homelab/vault/transit-evidence/bootstrap.sh trusted-keys
```

Commit what it writes. The demo workflow verifies against this folder, so it fails until the keys are here.

- Never delete a key file. Evidence signed with that key version would stop verifying.
- After a key rotation, run the script again and commit the new file. Transit signs with the new version at once, so evidence signed before that commit fails verification until it lands.

This folder plays the part of JFrog's trusted keys in the production design.
