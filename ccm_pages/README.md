Navigation: [DEDIS](https://github.com/dedis/doc) ::
[Student 2018](../README) ::
Claudio Loureiro - Cross-platform Application

# Claudio Loureiro - Cross-platform Application

In today’s Internet, most of the communication needs to be encrypted to ensure confidentiality and integrity of the data. Before a secured communication channel can be open between two devices (for example, between Alice and Bob), they need to exchange their public keys. Those permits Alice to send encrypted messages to Bob ensuring that he will be the only one who can decrypt it and vice versa. The problem with this exchange is that Bob needs to be certain that the public key that he receives is indeed Alice key. For example, a man-in-the-middle attacker can usurp the identity of Alice and sent his public key to Bob. Because Bob believes that he gets Alice key, he will send her confidential encrypted messages using the attacker’s key. Thus, the attacker will be able to read those messages using his private key. One solution that has been developed to prevent this type of attack was to create Certificate Authorities (CAs). Those entities deliver certificates that permit to prove that a key belongs to the appropriate device. Typically, a web server owner request a certificate from a CA so that he can prove to its clients that they use the right public key to communicate with him. Typically by now if a browser wants to establish a secure channel (using HTTPS) with a web server need to first get its certificate.

## Files

- [Report](report-2018_1-claudio_loureiro-ccm_pages.pdf)
- [Presentation](presentation-2018_1-claudio_loureiro-ccm_pages.pdf)
