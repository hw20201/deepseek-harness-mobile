package com.labteto.dshmobile.connection

/**
 * A reverse-proxy credential as the user typed it, in transit only.
 *
 * This is the pair for a proxy in front of a harness that demands HTTP Basic auth (nginx
 * `auth_basic`, say) — the username and password for the `Authorization: Basic …` header every
 * request to that endpoint carries. It is never persisted as a value: the form hands it to the
 * controller, the controller hands it to the probe and to `rememberHost`, and the platform stores
 * the password Keystore-encrypted (`ProxyCredentialStore` on Android) while the username lands on
 * [HostConfig.proxyUsername]. A remembered host re-reads its password from that store on every
 * connect, so nothing here ever has to be held across a process.
 */
data class ProxyCredentials(
    val username: String,
    val password: String,
) {
    /** True when there is a username to send; a blank username means "no proxy credential". */
    val present: Boolean get() = username.isNotBlank()
}
