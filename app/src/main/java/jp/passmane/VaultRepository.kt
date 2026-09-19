package jp.passmane

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import org.json.JSONObject
import javax.crypto.spec.SecretKeySpec

data class VaultItem(
    val id: Long = 0,
    val service: String,
    val url: String,
    val username: String,
    val password: String,
    val note: String
)

class VaultRepository(
    private val dao: VaultDao,
    private val crypto: CryptoManager
) {
    fun observeItems(key: SecretKeySpec): Flow<List<VaultItem>> = dao.observeAll().map { entries ->
        entries.mapNotNull { entry ->
            runCatching {
                val json = JSONObject(crypto.decrypt(EncryptedPayload(entry.ciphertext, entry.nonce), key).decodeToString())
                VaultItem(entry.id, json.getString("service"), json.getString("url"), json.getString("username"), json.getString("password"), json.getString("note"))
            }.getOrNull()
        }
    }

    suspend fun save(item: VaultItem, key: SecretKeySpec) {
        val json = JSONObject()
            .put("service", item.service).put("url", item.url).put("username", item.username)
            .put("password", item.password).put("note", item.note).toString()
        val encrypted = crypto.encrypt(json.encodeToByteArray(), key)
        dao.save(EncryptedEntry(item.id, encrypted.ciphertext, encrypted.nonce, System.currentTimeMillis()))
    }

    suspend fun delete(id: Long) = dao.delete(id)
}