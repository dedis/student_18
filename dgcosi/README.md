Navigation: [DEDIS](https://github.com/dedis/doc) ::
[Student 2018](../README.md) ::
Kopiga Rasiah	- DG CoSi

# Kopiga Rasiah	- Distributed Key Generation

One of the most important aspect of cryptography is secrecy. A large number of cryptographic applications requires a trusted authority to hold a secret. However, with the evolving attacks on the Internet, it is difficult to maintain such security that is entrusted to a single party. Secret sharing protocols is one of the solution that overcomes this problem. It involves a dealer who chooses a secret that he divides and share among the multiple servers, induc- ing the decentralization of the secret. Nevertheless, it still requires to trust a third party. A distributed key generation scheme settles this constraint by allocating the secret to not one dealer, but multiple servers. By doing so, a malicious attacker will need to break into multiples locations which slows down his intrusion process. However, this protection is incomplete for the entire life-time of the secret, as break-ins into subsets of servers are not completely excluded. In this project, I make contribution to an existing implementation of DKG protocol where I will propose a proactive secret shar- ing scheme that consists of updating the shares. By refreshing the shares, the information that the attacker has stolen previously becomes obsolete. Throughout this project report, I will explain comprehensively the DKG pro- tocol and how I gradually incorporate the proactive secret sharing into that protocol. I will terminate by enumerating possible future improvements. The implementation on which I contributed was developed by the Decen- tralized and Distributed Systems laboratory team. It is part of the library Kyber which provides a toolbox of advanced cryptographic primitives.

## Files

- [Report](report-2018_1-kopiga_rasiah-dkg.pdf)
- [Presentation](presentation-2018_1-kopiga_rasiah-dkg.pdf)
- [Code](code/dg-cosi)
