package jp.passmane

import android.content.Context
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import kotlinx.coroutines.flow.Flow

@Entity(tableName = "vault_entries")
data class EncryptedEntry(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val ciphertext: ByteArray,
    val nonce: ByteArray,
    val updatedAt: Long
)

@Dao
interface VaultDao {
    @Query("SELECT * FROM vault_entries ORDER BY updatedAt DESC")
    fun observeAll(): Flow<List<EncryptedEntry>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun save(entry: EncryptedEntry): Long

    @Query("DELETE FROM vault_entries WHERE id = :id")
    suspend fun delete(id: Long)
}

@Database(entities = [EncryptedEntry::class], version = 1, exportSchema = false)
abstract class VaultDatabase : RoomDatabase() {
    abstract fun vaultDao(): VaultDao

    companion object {
        fun create(context: Context): VaultDatabase = Room.databaseBuilder(
            context.applicationContext,
            VaultDatabase::class.java,
            "passmane-vault.db"
        ).build()
    }
}