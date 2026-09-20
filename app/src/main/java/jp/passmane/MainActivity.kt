package jp.passmane

import android.app.Application
import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.FileUpload
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import java.io.OutputStreamWriter
import javax.crypto.spec.SecretKeySpec

class MainActivity : FragmentActivity() {
    private val viewModel: VaultViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent { MaterialTheme { PassManeApp(viewModel, ::requestBiometricUnlock, ::requestBiometricEnrollment) } }
    }

    private fun requestBiometricUnlock() {
        val cipher = viewModel.biometricCipher() ?: return
        BiometricPrompt(this, ContextCompat.getMainExecutor(this), object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                result.cryptoObject?.cipher?.let(viewModel::unlockWithBiometric)
            }
        }).authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle("生体認証でロック解除")
                .setSubtitle("パスまねを解除します")
                .setNegativeButtonText("キャンセル")
                .build(),
            BiometricPrompt.CryptoObject(cipher)
        )
    }

    private fun requestBiometricEnrollment() {
        val cipher = viewModel.biometricEnrollmentCipher() ?: return
        BiometricPrompt(this, ContextCompat.getMainExecutor(this), object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                result.cryptoObject?.cipher?.let(viewModel::completeBiometricEnrollment)
            }
        }).authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle("生体認証を有効化")
                .setSubtitle("端末の生体認証で保管庫を解除できるようにします")
                .setNegativeButtonText("キャンセル")
                .build(),
            BiometricPrompt.CryptoObject(cipher)
        )
    }
}

class VaultViewModel(application: Application) : AndroidViewModel(application) {
    private val crypto = CryptoManager(application)
    private val repository = VaultRepository(VaultDatabase.create(application).vaultDao(), crypto)
    private val sessionKey = MutableStateFlow<SecretKeySpec?>(null)
    private val query = MutableStateFlow("")

    val configured: Boolean get() = crypto.isConfigured
    val unlocked: StateFlow<Boolean> = sessionKey
        .map { it != null }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), false)
    private val _items = MutableStateFlow<List<VaultItem>>(emptyList())
    val items: StateFlow<List<VaultItem>> = combine(_items, query) { entries, search ->
        entries.filter { search.isBlank() || it.service.contains(search, true) || it.username.contains(search, true) }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    fun setQuery(value: String) { query.value = value }

    fun setup(password: CharArray): String? = runCatching {
        val result = crypto.setup(password)
        openSession(result.dataKey)
        result.recoveryKey
    }.getOrNull()

    fun unlock(password: CharArray): Boolean {
        val key = crypto.unlock(password) ?: return false
        openSession(key)
        return true
    }

    fun biometricCipher() = crypto.biometricCipher()
    fun unlockWithBiometric(cipher: javax.crypto.Cipher) {
        crypto.completeBiometricUnlock(cipher)?.let(::openSession)
    }
    fun biometricEnrollmentCipher() = crypto.biometricEnrollmentCipher()
    fun completeBiometricEnrollment(cipher: javax.crypto.Cipher) {
        sessionKey.value?.let { crypto.completeBiometricEnrollment(cipher, it) }
    }

    fun reset(recoveryKey: String, password: CharArray): Boolean {
        val key = crypto.resetPassword(recoveryKey, password) ?: return false
        openSession(key)
        return true
    }

    fun save(item: VaultItem) {
        val key = sessionKey.value ?: return
        viewModelScope.launch { repository.save(item, key) }
    }

    fun delete(id: Long) { viewModelScope.launch { repository.delete(id) } }
    fun lock() { sessionKey.value = null; _items.value = emptyList() }

    fun importCsv(text: String) {
        val key = sessionKey.value ?: return
        val rows = text.lineSequence().map(::parseCsvLine).filter { it.size >= 5 }.toList()
        val dataRows = if (rows.firstOrNull()?.getOrNull(0)?.equals("service", ignoreCase = true) == true) rows.drop(1) else rows
        viewModelScope.launch {
            dataRows.forEach { columns ->
                repository.save(VaultItem(service = columns[0], url = columns[1], username = columns[2], password = columns[3], note = columns[4]), key)
            }
        }
    }

    private fun openSession(key: SecretKeySpec) {
        sessionKey.value = key
        viewModelScope.launch { repository.observeItems(key).collect { _items.value = it } }
    }
}

private fun parseCsvLine(line: String): List<String> {
    val fields = mutableListOf<String>()
    val current = StringBuilder()
    var inQuotes = false
    var i = 0
    while (i < line.length) {
        val c = line[i]
        when {
            inQuotes && c == '"' && i + 1 < line.length && line[i + 1] == '"' -> { current.append('"'); i++ }
            c == '"' -> inQuotes = !inQuotes
            c == ',' && !inQuotes -> { fields.add(current.toString()); current.clear() }
            else -> current.append(c)
        }
        i++
    }
    fields.add(current.toString())
    return fields
}

@Composable
private fun PassManeApp(viewModel: VaultViewModel, onBiometricUnlock: () -> Unit, onBiometricEnrollment: () -> Unit) {
    var recoveryKey by remember { mutableStateOf<String?>(null) }
    val unlocked by viewModel.unlocked.collectAsState()
    when {
        recoveryKey != null -> RecoveryKeyScreen(recoveryKey!!, onBiometricEnrollment) { recoveryKey = null }
        !viewModel.configured -> SetupScreen { password -> recoveryKey = viewModel.setup(password) }
        !unlocked -> UnlockScreen(onUnlock = viewModel::unlock, onReset = viewModel::reset, onBiometricUnlock = onBiometricUnlock)
        else -> VaultScreen(viewModel)
    }
}

@Composable
private fun SetupScreen(onSetup: (CharArray) -> Unit) {
    var password by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    AuthLayout("保管庫を作成") {
        PasswordField("マスターパスワード", password) { password = it }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        Button(onClick = {
            error = if (password.isBlank()) "マスターパスワードを入力してください。" else null
            if (error == null) onSetup(password.toCharArray())
        }, modifier = Modifier.fillMaxWidth()) { Text("保管庫を作成") }
    }
}

@Composable
private fun UnlockScreen(onUnlock: (CharArray) -> Boolean, onReset: (String, CharArray) -> Boolean, onBiometricUnlock: () -> Unit) {
    var password by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var resetMode by remember { mutableStateOf(false) }
    var recovery by remember { mutableStateOf("") }
    var newPassword by remember { mutableStateOf("") }
    AuthLayout(if (resetMode) "復旧キーで変更" else "パスまね") {
        if (resetMode) {
            OutlinedTextField(recovery, { recovery = it }, label = { Text("復旧キー") }, modifier = Modifier.fillMaxWidth())
            PasswordField("新しいマスターパスワード", newPassword) { newPassword = it }
        } else {
            PasswordField("マスターパスワード", password) { password = it }
        }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        Button(onClick = {
            val success = if (resetMode) onReset(recovery, newPassword.toCharArray()) else onUnlock(password.toCharArray())
            if (!success) error = "入力内容を確認してください。"
        }, modifier = Modifier.fillMaxWidth()) { Text(if (resetMode) "変更する" else "ロックを解除") }
        if (!resetMode) TextButton(onClick = onBiometricUnlock) { Text("生体認証で解除") }
        TextButton(onClick = { resetMode = !resetMode; error = null }) {
            Text(if (resetMode) "マスターパスワードで解除" else "マスターパスワードを忘れた場合")
        }
    }
}

@Composable
private fun RecoveryKeyScreen(key: String, onEnableBiometrics: () -> Unit, onContinue: () -> Unit) {
    AuthLayout("復旧キーを保管") {
        Text("このキーはマスターパスワードを忘れたときに必要です。安全な場所に保管してください。")
        Card(modifier = Modifier.fillMaxWidth()) { Text(key, modifier = Modifier.padding(16.dp)) }
        TextButton(onClick = onEnableBiometrics, modifier = Modifier.fillMaxWidth()) { Text("生体認証を有効にする") }
        Button(onClick = onContinue, modifier = Modifier.fillMaxWidth()) { Text("保管しました") }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun VaultScreen(viewModel: VaultViewModel) {
    val entries by viewModel.items.collectAsState()
    var editor by remember { mutableStateOf<VaultItem?>(null) }
    var searchText by remember { mutableStateOf("") }
    val context = LocalContext.current
    val exporter = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/csv")) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        val result = runCatching {
            context.contentResolver.openOutputStream(uri)?.use { stream ->
                OutputStreamWriter(stream).use { writer ->
                    writer.appendLine("service,url,username,password,note")
                    entries.forEach { item -> writer.appendLine(listOf(item.service, item.url, item.username, item.password, item.note).joinToString(",") { "\"${it.replace("\"", "\"\"")}\"" }) }
                }
            }
        }
        Toast.makeText(context, if (result.isSuccess) "CSVを出力しました" else "CSV出力に失敗しました: ${result.exceptionOrNull()?.message}", Toast.LENGTH_LONG).show()
    }
    val importer = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        val result = runCatching {
            context.contentResolver.openInputStream(uri)?.use { stream ->
                viewModel.importCsv(stream.reader(Charsets.UTF_8).readText())
            }
        }
        Toast.makeText(context, if (result.isSuccess) "CSVを取り込みました" else "CSV取り込みに失敗しました: ${result.exceptionOrNull()?.message}", Toast.LENGTH_LONG).show()
    }
    Scaffold(
        topBar = { CenterAlignedTopAppBar(title = { Text("パスまね") }, navigationIcon = { IconButton(viewModel::lock) { Icon(Icons.Default.Lock, "ロック") } }, actions = {
            IconButton({
                val started = runCatching { importer.launch("text/*") }
                if (started.isFailure) Toast.makeText(context, "取り込み画面を開けませんでした: ${started.exceptionOrNull()?.message}", Toast.LENGTH_LONG).show()
            }) { Icon(Icons.Default.FileUpload, "CSV取り込み") }
            IconButton({
                val started = runCatching { exporter.launch("passmane.csv") }
                if (started.isFailure) Toast.makeText(context, "保存先選択画面を開けませんでした: ${started.exceptionOrNull()?.message}", Toast.LENGTH_LONG).show()
            }) { Icon(Icons.Default.FileDownload, "CSV出力") }
        }) },
        floatingActionButton = { FloatingActionButton(onClick = { editor = VaultItem(service = "", url = "", username = "", password = "", note = "") }) { Icon(Icons.Default.Add, "登録") } }
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).padding(horizontal = 16.dp)) {
            OutlinedTextField(searchText, { searchText = it; viewModel.setQuery(it) }, label = { Text("検索") }, modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp))
            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(entries, key = { it.id }) { item ->
                    Card(Modifier.fillMaxWidth().clickable { editor = item }) {
                        Column(Modifier.padding(16.dp)) {
                            Text(item.service.ifBlank { "名称なし" }, style = MaterialTheme.typography.titleMedium)
                            Text(item.username, style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
            }
        }
    }
    editor?.let { item -> EntryDialog(item, onDismiss = { editor = null }, onSave = { viewModel.save(it); editor = null }, onDelete = { if (item.id != 0L) viewModel.delete(item.id); editor = null }) }
}

@Composable
private fun EntryDialog(item: VaultItem, onDismiss: () -> Unit, onSave: (VaultItem) -> Unit, onDelete: () -> Unit) {
    var service by remember(item.id) { mutableStateOf(item.service) }
    var url by remember(item.id) { mutableStateOf(item.url) }
    var username by remember(item.id) { mutableStateOf(item.username) }
    var password by remember(item.id) { mutableStateOf(item.password) }
    var note by remember(item.id) { mutableStateOf(item.note) }
    AlertDialog(onDismissRequest = onDismiss, title = { Text(if (item.id == 0L) "新規登録" else "編集") }, text = {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(service, { service = it }, label = { Text("サービス名") })
            OutlinedTextField(url, { url = it }, label = { Text("URL") })
            OutlinedTextField(username, { username = it }, label = { Text("ユーザー名") })
            PasswordField("パスワード", password) { password = it }
            OutlinedTextField(note, { note = it }, label = { Text("メモ") })
        }
    }, confirmButton = { TextButton(onClick = { onSave(VaultItem(item.id, service, url, username, password, note)) }) { Text("保存") } }, dismissButton = {
        Row {
            if (item.id != 0L) IconButton(onClick = onDelete) { Icon(Icons.Default.Delete, "削除") }
            TextButton(onClick = onDismiss) { Text("キャンセル") }
        }
    })
}

@Composable
private fun PasswordField(label: String, value: String, onValueChange: (String) -> Unit) {
    var visible by remember { mutableStateOf(false) }
    OutlinedTextField(value, onValueChange, label = { Text(label) }, modifier = Modifier.fillMaxWidth(), visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(), trailingIcon = { IconButton({ visible = !visible }) { Icon(if (visible) Icons.Default.VisibilityOff else Icons.Default.Visibility, "表示を切替") } })
}

@Composable
private fun AuthLayout(title: String, content: @Composable ColumnScope.() -> Unit) {
    Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
        Text(title, style = MaterialTheme.typography.headlineMedium, modifier = Modifier.padding(bottom = 24.dp))
        Column(verticalArrangement = Arrangement.spacedBy(12.dp), content = content)
    }
}