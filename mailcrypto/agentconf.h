#ifndef AGENTCONF_H
#define AGENTCONF_H

// gpg-agent.conf of the S/MIME home. Written by the S/MIME engine and — before
// it starts that home's agent at app start — by the OpenPGP engine, so it has
// to be ONE text: two spellings would rewrite the file on every start.
//
// allow-loopback-pinentry is critical for .p12 import: gpgsm hands the private
// key to the agent, which only accepts the loopback passphrase with it —
// without it the key is silently NOT stored (certs import, 0 secret keys).
// The zero TTLs keep an unlocked key in agent memory for one operation only.
static const char kSmimeAgentConf[] =
    "allow-loopback-pinentry\n"
    "default-cache-ttl 0\n"
    "max-cache-ttl 0\n"
    "ignore-cache-for-signing\n"
    "disable-scdaemon\n";

#endif
