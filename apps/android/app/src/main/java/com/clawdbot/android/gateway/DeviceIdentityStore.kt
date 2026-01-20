package com.clawdbot.android.gateway

import android.content.Context
import android.util.Base64
import java.io.File
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Provider
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.jce.provider.BouncyCastleProvider

@Serializable
data class DeviceIdentity(
  val deviceId: String,
  val publicKeyRawBase64: String,
  val privateKeyPkcs8Base64: String,
  val createdAtMs: Long,
)

class DeviceIdentityStore(context: Context) {
  private fun ensureBcProvider(): Provider {
    // Use a per-call provider to avoid mutating global provider order.
    // Some devices/ROMs don't expose Ed25519 via the default JCA providers.
    return BouncyCastleProvider()
  }

  private val json = Json { ignoreUnknownKeys = true }
  private val identityFile = File(context.filesDir, "clawdbot/identity/device.json")

  @Synchronized
  fun loadOrCreate(): DeviceIdentity {
    val existing = load()
    if (existing != null) {
      val derived = deriveDeviceId(existing.publicKeyRawBase64)
      if (derived != null && derived != existing.deviceId) {
        val updated = existing.copy(deviceId = derived)
        save(updated)
        return updated
      }
      return existing
    }
    val fresh = generate()
    save(fresh)
    return fresh
  }

  fun signPayload(payload: String, identity: DeviceIdentity): String? {
    return try {
      val privateKeyBytes = Base64.decode(identity.privateKeyPkcs8Base64, Base64.DEFAULT)
      val rawPrivateKey = stripPkcs8Prefix(privateKeyBytes)

      val privateKeyParams = Ed25519PrivateKeyParameters(rawPrivateKey, 0)
      val signer = Ed25519Signer()
      signer.init(true, privateKeyParams)
      val message = payload.toByteArray(Charsets.UTF_8)
      signer.update(message, 0, message.size)
      val signature = signer.generateSignature()
      base64UrlEncode(signature)
    } catch (_: Throwable) {
      null
    }
  }

  fun publicKeyBase64Url(identity: DeviceIdentity): String? {
    return try {
      val decoded = Base64.decode(identity.publicKeyRawBase64, Base64.DEFAULT)
      val raw = stripSpkiPrefix(decoded)
      base64UrlEncode(raw)
    } catch (_: Throwable) {
      null
    }
  }

  private fun load(): DeviceIdentity? {
    return try {
      if (!identityFile.exists()) return null
      val raw = identityFile.readText(Charsets.UTF_8)
      val decoded = json.decodeFromString(DeviceIdentity.serializer(), raw)
      if (decoded.deviceId.isBlank() ||
        decoded.publicKeyRawBase64.isBlank() ||
        decoded.privateKeyPkcs8Base64.isBlank()
      ) {
        null
      } else {
        decoded
      }
    } catch (_: Throwable) {
      null
    }
  }

  private fun save(identity: DeviceIdentity) {
    try {
      identityFile.parentFile?.mkdirs()
      val encoded = json.encodeToString(DeviceIdentity.serializer(), identity)
      identityFile.writeText(encoded, Charsets.UTF_8)
    } catch (_: Throwable) {
      // best-effort only
    }
  }

  private fun generate(): DeviceIdentity {
    val provider = ensureBcProvider()
    val keyPair = KeyPairGenerator.getInstance("Ed25519", provider).generateKeyPair()

    val spki = keyPair.public.encoded
    val rawPublic = stripSpkiPrefix(spki)
    val deviceId = sha256Hex(rawPublic)
    val privateKey = keyPair.private.encoded

    return DeviceIdentity(
      deviceId = deviceId,
      publicKeyRawBase64 = Base64.encodeToString(rawPublic, Base64.NO_WRAP),
      privateKeyPkcs8Base64 = Base64.encodeToString(privateKey, Base64.NO_WRAP),
      createdAtMs = System.currentTimeMillis(),
    )
  }

  private fun deriveDeviceId(publicKeyRawBase64: String): String? {
    return try {
      val decoded = Base64.decode(publicKeyRawBase64, Base64.DEFAULT)
      val raw = stripSpkiPrefix(decoded)
      sha256Hex(raw)
    } catch (_: Throwable) {
      null
    }
  }

  private fun stripSpkiPrefix(spki: ByteArray): ByteArray {
    if (spki.size == ED25519_SPKI_PREFIX.size + 32 &&
      spki.copyOfRange(0, ED25519_SPKI_PREFIX.size).contentEquals(ED25519_SPKI_PREFIX)
    ) {
      return spki.copyOfRange(ED25519_SPKI_PREFIX.size, spki.size)
    }
    return spki
  }

  private fun stripPkcs8Prefix(pkcs8: ByteArray): ByteArray {
    // PKCS8 Ed25519 private key is 48 bytes: 16-byte prefix + 32-byte raw key
    if (pkcs8.size == ED25519_PKCS8_PREFIX.size + 32 &&
      pkcs8.copyOfRange(0, ED25519_PKCS8_PREFIX.size).contentEquals(ED25519_PKCS8_PREFIX)
    ) {
      return pkcs8.copyOfRange(ED25519_PKCS8_PREFIX.size, pkcs8.size)
    }
    // Already raw 32 bytes
    if (pkcs8.size == 32) {
      return pkcs8
    }
    return pkcs8
  }

  private fun sha256Hex(data: ByteArray): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(data)
    val out = StringBuilder(digest.size * 2)
    for (byte in digest) out.append(String.format("%02x", byte))
    return out.toString()
  }

  private fun base64UrlEncode(data: ByteArray): String {
    return Base64.encodeToString(data, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
  }

  companion object {
    private val ED25519_SPKI_PREFIX =
      byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)

    // PKCS8 prefix for Ed25519: 302e020100300506032b657004220420
    private val ED25519_PKCS8_PREFIX =
      byteArrayOf(
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
      )
  }
}

