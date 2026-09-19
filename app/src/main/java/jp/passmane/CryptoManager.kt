package jp.passmane

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.SecureRandom
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class CryptoManager(context: Context) {
    private val preferences = context.getSharedPreferences("vault_config", Context.MODE_PRIVATE)
    private val random = SecureRandom()

    val isConfigured: Boolean get() = preferences.contains("salt")

    fun setup(masterPassword: CharArray): SetupResult {
        require(masterPassword.isNotEmpty()) { "マスターパスワードを入力してください。" }
        val dataKey = randomBytes(32)
        val recoveryKey = Base64.encodeToString(randomBytes(32), Base64.NO_WRAP or Base64.URL_SAFE)
        storeWrappedKeys(dataKey, masterPassword, recoveryKey)
        masterPassword.fill('\u0000')
        return SetupResult(recoveryKey, SecretKeySpec(dataKey, "AES"))
    }

    fun unlock(masterPassword: CharArray): SecretKeySpec? = runCatching {
        val salt = decode("salt")
        val wrapped = decode("password_wrapped")
        val nonce = decode("password_nonce")
        val dataKey = decrypt(wrapped, nonce, deriveKey(masterPassword, salt))
        masterPassword.fill('\u0000')
        SecretKeySpec(dataKey, "AES")
    }.getOrNull()

    fun resetPassword(recoveryKey: String, newPassword: CharArray): SecretKeySpec? = runCatching {
        require(newPassword.isNotEmpty())
        val oldSalt = decode("salt")
        val dataKey = decrypt(
            decode("recovery_wrapped"),
            decode("recovery_nonce"),
            deriveKey(recoveryKey.toCharArray(), oldSalt)
        )
        storeWrappedKeys(dataKey, newPassword, recoveryKey)
        newPassword.fill('\u0000')
        SecretKeySpec(dataKey, "AES")
    }.getOrNull()

    fun encrypt(plainText: ByteArray, key: SecretKeySpec): EncryptedPayload {
        val nonce = randomBytes(12)
        return EncryptedPayload(encrypt(plainText, nonce, key), nonce)
    }

    fun decrypt(payload: EncryptedPayload, key: SecretKeySpec): ByteArray =
        decrypt(payload.ciphertext, payload.nonce, key)

    fun biometricCipher(): Cipher? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M || !preferences.contains("biometric_wrapped")) return null
        return runCatching {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val key = keyStore.getKey(BIOMETRIC_KEY_ALIAS, null) as? javax.crypto.SecretKey ?: return null
            Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, decode("biometric_nonce")))
            }
        }.getOrNull()
    }

    fun completeBiometricUnlock(cipher: Cipher): SecretKeySpec? = runCatching {
        SecretKeySpec(cipher.doFinal(decode("biometric_wrapped")), "AES")
    }.getOrNull()

    fun biometricEnrollmentCipher(): Cipher? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return null
        return runCatching {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (keyStore.containsAlias(BIOMETRIC_KEY_ALIAS)) keyStore.deleteEntry(BIOMETRIC_KEY_ALIAS)
            val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            generator.init(
                KeyGenParameterSpec.Builder(BIOMETRIC_KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setUserAuthenticationRequired(true)
                    .build()
            )
            Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, generator.generateKey()) }
        }.getOrNull()
    }

    fun completeBiometricEnrollment(cipher: Cipher, dataKey: SecretKeySpec) {
        val encrypted = cipher.doFinal(dataKey.encoded)
        preferences.edit()
            .putString("biometric_wrapped", encode(encrypted))
            .putString("biometric_nonce", encode(cipher.iv))
            .apply()
    }

    private fun storeWrappedKeys(dataKey: ByteArray, password: CharArray, recoveryKey: String) {
        val salt = randomBytes(16)
        val passwordNonce = randomBytes(12)
        val passwordPayload = EncryptedPayload(
            encrypt(dataKey, passwordNonce, deriveKey(password, salt)),
            passwordNonce
        )
        val recoveryNonce = randomBytes(12)
        val recoveryPayload = EncryptedPayload(
            encrypt(dataKey, recoveryNonce, deriveKey(recoveryKey.toCharArray(), salt)),
            recoveryNonce
        )
        preferences.edit()
            .putString("salt", encode(salt))
            .putString("password_wrapped", encode(passwordPayload.ciphertext))
            .putString("password_nonce", encode(passwordPayload.nonce))
            .putString("recovery_wrapped", encode(recoveryPayload.ciphertext))
            .putString("recovery_nonce", encode(recoveryPayload.nonce))
            .apply()
    }

    private fun deriveKey(password: CharArray, salt: ByteArray): SecretKeySpec {
        val spec = PBEKeySpec(password, salt, 210_000, 256)
        val bytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        spec.clearPassword()
        return SecretKeySpec(bytes, "AES")
    }

    private fun encrypt(data: ByteArray, nonce: ByteArray, key: SecretKeySpec): ByteArray =
        Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, nonce))
            doFinal(data)
        }

    private fun decrypt(data: ByteArray, nonce: ByteArray, key: SecretKeySpec): ByteArray =
        Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, nonce))
            doFinal(data)
        }

    private fun randomBytes(size: Int) = ByteArray(size).also(random::nextBytes)
    private fun encode(value: ByteArray) = Base64.encodeToString(value, Base64.NO_WRAP)
    private fun decode(key: String) = Base64.decode(requireNotNull(preferences.getString(key, null)), Base64.NO_WRAP)

    private companion object {
        const val BIOMETRIC_KEY_ALIAS = "passmane_biometric_key"
    }
}

data class EncryptedPayload(val ciphertext: ByteArray, val nonce: ByteArray)
data class SetupResult(val recoveryKey: String, val dataKey: SecretKeySpec)