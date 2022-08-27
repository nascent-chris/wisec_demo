# Cryptographic Cipher 

Cipher Recommendations
* Stream cipher `ChaCha20` with `Poly1305` Message Authentication (i.e. `ChaCha20-Poly1305`)
* Requires the use of a 96-bit nonce that must be unique per message
* Requires every device share the same private key `K` described below
# Key Requirements
Each key `K` in this scheme shall be
* 256 bits in length
* unique between networks (i.e. no two networks shall have the same `K`)
* copied to each device _within a network_ during programming
* maintained unchanged on the device throughout its lifespan
* shared among all devices wishing to communicate (e.g. all devices on a network have the same immutable `K`)

# Nonce Requirements
* May be shared plaintext (e.g. included in the message header)
* Must be unique per message (!)
  * Per [RFC 7539](https://www.rfc-editor.org/rfc/rfc7539#section-4) "The most important security consideration in implementing this document is the uniqueness of the nonce used in ChaCha20".  It is imperative that a nonce is not ever repeated.  Given that a nonce must be 96 bits, we propose the following nonce generation scheme:

## Nonce Generation Scheme
A nonce generation scheme is described below.  While it may be tempting to randomly generate all 96 bits, this will expose the system to the possibility of a [birthday attack](https://en.wikipedia.org/wiki/Birthday_attack) as the likelihood of a nonce collision increases with the number of total messages sent.  For this reason, generating unique nonces deterministically is preferred.

| Upper 48 bits                                          | Lower 48 bits      |                    |
| ------------------------------------------------------ | ------------------ | ------------------ |
| 48 bits (95-48)                                        | 40 bits (47-8)     | 8 bits (7-0)       |
| Lower 48-bits of 64-bit UTC epoch time in milliseconds | randomly generated | unique ID per node |

This scheme provides 2^40 unique messages (approximately 1.1 trillion) per millisecond for 2^48 milliseconds (approximately 8919 years) per device.  Note that, for networks requiring more than 2^8 nodes, the width of the ID field can be adjusted accordingly.


### Nonce Generation Without Current Time
*Note that this mode should be considered temporary, as the likelihood of nonce collisions increases with the number of messages sent (as described above).*

If a device is unable to synchronize its system clock or has not yet done so (e.g. after reboot and/or there is no time provider available), the recommendation is to set the upper two bytes to `0xFFFF`, counting down for each message, and randomly generating the other 32 bits.  This ensures that the randomly generated bits will not risk colliding with the system clock for the life of the device.

A modification of this scheme could include starting at a sufficiently large random value for the upper two bytes (e.g. in the range 0xF000 to 0xFFFF) and counting down for each message from there.
