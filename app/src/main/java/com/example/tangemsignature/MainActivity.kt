package com.example.tangemsignature

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.tangem.TangemSdk
import com.tangem.common.CompletionResult
import com.tangem.common.extensions.toHexString
import java.security.MessageDigest

class MainActivity : ComponentActivity() {
    private lateinit var sdk: TangemSdk

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        sdk = TangemSdk.init(this)
        setContent {
            MaterialTheme {
                SignScreen { message, onResult -> signMessage(message, onResult) }
            }
        }
    }

    private fun signMessage(message: String, onResult: (String) -> Unit) {
        val hash = MessageDigest.getInstance("SHA-256").digest(message.toByteArray())
        sdk.scanCard { scanResult ->
            when (scanResult) {
                is CompletionResult.Success -> {
                    val card = scanResult.data
                    val wallet = card.wallets.firstOrNull()
                    if (wallet == null) {
                        runOnUiThread { onResult("No wallet found") }
                        return@scanCard
                    }
                    sdk.sign(hash, wallet.publicKey, card.cardId, null, null) { signResult ->
                        val text = when (signResult) {
                            is CompletionResult.Success -> signResult.data.signature.toHexString()
                            is CompletionResult.Failure -> signResult.error.toString()
                        }
                        runOnUiThread { onResult(text) }
                    }
                }
                is CompletionResult.Failure -> runOnUiThread { onResult(scanResult.error.toString()) }
            }
        }
    }
}

@Composable
fun SignScreen(onSign: (String, (String) -> Unit) -> Unit) {
    var message by remember { mutableStateOf("") }
    var signature by remember { mutableStateOf("") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        OutlinedTextField(
            value = message,
            onValueChange = { message = it },
            label = { Text("Message") },
            modifier = Modifier.fillMaxWidth()
        )
        Button(onClick = { onSign(message) { signature = it } }) {
            Text("Sign")
        }
        Text("Signature: $signature")
    }
}
