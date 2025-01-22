# shamir - Shamir’s Secret Sharing in Go

> **Attention**: This implementation is not hardened against side-channel
> attacks. Be cautious when using it in security-critical applications.

This is a Go implementation of Shamir's Secret Sharing algorithm. It allows you
to split a secret into multiple shares, such that a minimum number of shares is
required to reconstruct the secret. By using GF(2^16) instead of GF(2^8), this
implementation can create more than 255 distinct shares.