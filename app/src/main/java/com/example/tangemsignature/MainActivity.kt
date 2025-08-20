package com.example.tangemsignature

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Base64
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.tangem.TangemSdk
import com.tangem.common.CompletionResult
import com.tangem.common.card.EllipticCurve
import com.tangem.crypto.hdWallet.DerivationPath
import com.tangem.common.core.CardSession
import com.tangem.operations.sign.SignHashCommand
import com.tangem.operations.sign.SignHashResponse
import com.tangem.sdk.extensions.init
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.security.KeyFactory
import java.util.concurrent.atomic.AtomicBoolean

private fun CardSession.performCommand(
    signHashCommand: SignHashCommand,
    function: (CompletionResult<SignHashResponse>) -> Unit
) {
}

class MainActivity : ComponentActivity() {

    private lateinit var sdk: TangemSdk
    private val mainHandler by lazy { Handler(Looper.getMainLooper()) }
    private val isWorking = AtomicBoolean(false)

    private val targetAddress = "bc1q4fj5w4vunuar7ep76yxa7vchn3xryrcgu8jnld"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        sdk = TangemSdk.init(this, com.tangem.common.core.Config())

        setContent {
            MaterialTheme {
                SignScreen(
                    initialMessage = "",
                    targetAddr = targetAddress,
                    onSign = { msg, addr, setText -> signForAddress(msg, addr, setText) },
                    onCopy = { label, text -> copyToClipboard(label, text) }
                )
            }
        }
    }

    private fun copyToClipboard(label: String, text: String) {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText(label, text))
    }

    private fun signForAddress(message: String, address: String, onResult: (String) -> Unit) {
        if (!isWorking.compareAndSet(false, true)) {
            onResult("⏳ Une opération est déjà en cours…")
            return
        }

        val digest = bitcoinMessageDigest(message)
        val dec = decodeBech32P2WPKH(address)
        if (dec == null) {
            finishWork { onResult("Adresse cible invalide.") }
            return
        }

        sdk.scanCard { scanResult ->
            when (scanResult) {
                is CompletionResult.Success<*> -> {
                    val card = scanResult.data as? com.tangem.common.card.Card
                    val wallet = card?.wallets?.firstOrNull { it.curve == EllipticCurve.Secp256k1 }
                    if (card == null || wallet == null) {
                        finishWork { onResult("❌ Aucun wallet secp256k1 trouvé.") }
                        return@scanCard
                    }

                    val cardId = card.cardId!!
                    val masterWalletPub = wallet.publicKey

                    // chemins BIP84 à tester
                    val derivationPaths = listOf(
                        DerivationPath("m/84'/0'/0'/0/0"),
                        DerivationPath("m/84'/0'/0'/0/1"),
                        DerivationPath("m/84'/0'/0'/1/0")
                    )

                    fun tryNextPath(index: Int) {
                        if (index >= derivationPaths.size) {
                            finishWork { onResult("❌ Aucun chemin BIP84 testé n’a correspondu à $address") }
                            return
                        }

                        val path = derivationPaths[index]

                        sdk.startSessionWithRunnable(
                            object : com.tangem.common.core.CardSessionRunnable<SignHashResponse> {
                                override fun run(
                                    session: CardSession,
                                    callback: (CompletionResult<SignHashResponse>) -> Unit
                                ) {
                                    session.performCommand(
                                        SignHashCommand(
                                            hash = digest,
                                            walletPublicKey = masterWalletPub,
                                            derivationPath = path
                                        )
                                    ) { signResult: CompletionResult<SignHashResponse> ->
                                        callback(signResult)
                                    }
                                }
                            },
                            initialMessage = null,
                            cardId = cardId
                        ) { signResult ->
                            when (signResult) {
                                is CompletionResult.Success -> {
                                    val response = signResult.data
                                    val rawSig = response.signature
                                    val der = raw64ToDerLowS(rawSig)
                                    val base64 = Base64.encodeToString(der, Base64.NO_WRAP)
                                    val derivedPubKey = response.walletPublicKey ?: masterWalletPub
                                    val derivedAddr = p2wpkhAddress(dec.hrp, compressIfNeeded(derivedPubKey))

                                    mainHandler.post {
                                        onResult("🔎 Test chemin $path → adresse dérivée $derivedAddr")
                                    }

                                    if (derivedAddr == address) {
                                        mainHandler.post {
                                            finishWork {
                                                onResult(
                                                    """
                                                ✅ Chemin trouvé: $path
                                                Adresse: $derivedAddr
                                                Signature DER (base64): $base64
                                                """.trimIndent()
                                                )
                                            }
                                        }
                                    } else {
                                        tryNextPath(index + 1)
                                    }
                                }
                                is CompletionResult.Failure -> {
                                    mainHandler.post {
                                        onResult("⚠️ Erreur signature avec chemin $path: ${signResult.error}")
                                    }
                                    tryNextPath(index + 1)
                                }
                            }
                        }
                    }

                    // on commence avec le premier chemin
                    tryNextPath(0)
                }

                is CompletionResult.Failure -> {
                    finishWork { onResult("Erreur scan: ${scanResult.error}") }
                }
            }
        }
    }

    private fun finishWork(action: () -> Unit) {
        runOnUiThread { try { action() } finally { isWorking.set(false) } }
    }

    // --- Crypto helpers manquants ---

    private fun bitcoinMessageDigest(message: String): ByteArray {
        val prefix = "Bitcoin Signed Message:\n"
        val data = ByteArrayOutputStream()
        data.write(varInt(prefix.length))
        data.write(prefix.toByteArray())
        data.write(varInt(message.length))
        data.write(message.toByteArray())
        return sha256(sha256(data.toByteArray()))
    }

    private fun sha256(input: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(input)

    private fun ripemd160(input: ByteArray): ByteArray =
        MessageDigest.getInstance("RIPEMD160").digest(input)

    private fun hash160(input: ByteArray): ByteArray = ripemd160(sha256(input))

    private fun varInt(i: Int): ByteArray {
        return if (i < 0xfd) byteArrayOf(i.toByte())
        else if (i <= 0xffff) ByteBuffer.allocate(3).order(ByteOrder.LITTLE_ENDIAN).put(0xfd.toByte()).putShort(i.toShort()).array()
        else ByteBuffer.allocate(5).order(ByteOrder.LITTLE_ENDIAN).put(0xfe.toByte()).putInt(i).array()
    }

    private fun compressIfNeeded(pubKey: ByteArray): ByteArray {
        if (pubKey.size == 33) return pubKey // déjà compressé
        val kf = KeyFactory.getInstance("EC")
        val pk = kf.generatePublic(X509EncodedKeySpec(pubKey)) as ECPublicKey
        val x = pk.w.affineX
        val y = pk.w.affineY
        val prefix: Byte = if (y.testBit(0)) 0x03 else 0x02
        val xb = x.toByteArray()
        val xBytes = if (xb.size == 33 && xb[0] == 0.toByte()) xb.copyOfRange(1, 33) else xb
        return byteArrayOf(prefix) + xBytes
    }

    private fun raw64ToDerLowS(sig: ByteArray): ByteArray {
        if (sig.size != 64) return sig
        val r = sig.copyOfRange(0, 32)
        val s = sig.copyOfRange(32, 64)
        val rBig = BigInteger(1, r)
        val sBig = BigInteger(1, s)
        val halfOrder = BigInteger(
            "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
            16
        )
        val two = BigInteger.valueOf(2)
        val sLow = if (sBig > halfOrder) {
            BigInteger.ZERO.subtract(sBig.subtract(halfOrder.multiply(two)))
        } else {
            sBig
        }

        val rDer = derInteger(rBig)
        val sDer = derInteger(sLow)
        val seq = byteArrayOf(0x30, (rDer.size + sDer.size).toByte())
        return seq + rDer + sDer
    }

    private fun derInteger(x: BigInteger): ByteArray {
        var bytes = x.toByteArray()
        if (bytes[0].toInt() and 0x80 != 0) {
            bytes = byteArrayOf(0) + bytes
        }
        return byteArrayOf(0x02, bytes.size.toByte()) + bytes
    }

    // --- Bech32 déjà dans ton code ---
    private data class Bech32Decoded(val hrp: String, val program20: ByteArray)
    private val charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    private val charsetRev = charset.withIndex().associate { it.value to it.index }

    private fun p2wpkhAddress(hrp: String, pubCompressed: ByteArray): String {
        val program = hash160(pubCompressed)
        return bech32EncodeWitnessV0(hrp, program)
    }

    private fun bech32EncodeWitnessV0(hrp: String, program: ByteArray): String {
        val converted = convertBits(program.map { it.toInt() and 0xFF }.toIntArray(), 8, 5, true) ?: return ""
        val data = IntArray(1) { 0 } + converted.map { it.toInt() and 0xFF }.toIntArray()
        return bech32Encode(hrp, data)
    }

    private fun decodeBech32P2WPKH(addr: String): Bech32Decoded? {
        val lower = addr.lowercase()
        val pos = lower.lastIndexOf('1')
        if (pos < 1) return null
        val hrp = lower.substring(0, pos)
        val data = lower.substring(pos + 1)
        val decoded5 = data.map { charsetRev[it] ?: return null }.toIntArray()
        if (!bech32VerifyChecksum(hrp, decoded5)) return null
        val noChecksum = decoded5.copyOf(decoded5.size - 6)
        if (noChecksum.isEmpty()) return null
        val ver = noChecksum[0]
        if (ver != 0) return null
        val prog5 = noChecksum.sliceArray(1 until noChecksum.size)
        val prog8 = convertBits(prog5, 5, 8, false) ?: return null
        if (prog8.size != 20) return null
        return Bech32Decoded(hrp, prog8)
    }

    private fun bech32HrpExpand(hrp: String): IntArray {
        val out = ArrayList<Int>()
        for (c in hrp) out += (c.code shr 5)
        out += 0
        for (c in hrp) out += (c.code and 31)
        return out.toIntArray()
    }

    private fun bech32Polymod(values: IntArray): Int {
        var chk = 1
        val gen = intArrayOf(0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
        for (v in values) {
            val b = (chk shr 25) and 0xff
            chk = (chk and 0x1ffffff) shl 5 xor v
            for (i in 0..4) {
                if (((b shr i) and 1) != 0) chk = chk xor gen[i]
            }
        }
        return chk
    }

    private fun bech32CreateChecksum(hrp: String, data: IntArray): IntArray {
        val values = bech32HrpExpand(hrp) + data + IntArray(6) { 0 }
        val mod = bech32Polymod(values) xor 1
        val ret = IntArray(6)
        for (i in 0..5) ret[i] = (mod shr (5 * (5 - i))) and 31
        return ret
    }

    private fun bech32Encode(hrp: String, data: IntArray): String {
        val checksum = bech32CreateChecksum(hrp, data)
        val combined = data + checksum
        val chars = buildString { combined.forEach { append(charset[it]) } }
        return hrp + "1" + chars
    }

    private fun bech32VerifyChecksum(hrp: String, data: IntArray): Boolean {
        return bech32Polymod(bech32HrpExpand(hrp) + data) == 1
    }

    private fun convertBits(data: IntArray, from: Int, to: Int, pad: Boolean): ByteArray? {
        var acc = 0
        var bits = 0
        val ret = ArrayList<Byte>()
        val maxv = (1 shl to) - 1
        val maxAcc = (1 shl (from + to - 1)) - 1
        for (value in data) {
            if (value < 0 || (value shr from) != 0) return null
            acc = ((acc shl from) or value) and maxAcc
            bits += from
            while (bits >= to) {
                bits -= to
                ret += ((acc shr bits) and maxv).toByte()
            }
        }
        if (pad) {
            if (bits > 0) ret += ((acc shl (to - bits)) and maxv).toByte()
        } else if (bits >= from || ((acc shl (to - bits)) and maxv) != 0) {
            return null
        }
        return ret.toByteArray()
    }
// ---------------- UI ----------------
@Composable
fun SignScreen(
    initialMessage: String,
    targetAddr: String,
    onSign: (String, String, (String) -> Unit) -> Unit,
    onCopy: (String, String) -> Unit
) {
    var message by remember { mutableStateOf(initialMessage) }
    var resultText by remember { mutableStateOf("") }
    var address by remember { mutableStateOf(targetAddr) }

    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        OutlinedTextField(
            value = message,
            onValueChange = { message = it },
            label = { Text("Message (Bitcoin Signed Message)") },
            modifier = Modifier.fillMaxWidth()
        )
        OutlinedTextField(
            value = address,
            onValueChange = { address = it },
            label = { Text("Adresse Bitcoin cible (bc1q…)") },
            modifier = Modifier.fillMaxWidth()
        )
        Row {
            Button(onClick = { onSign(message, address) { resultText = it } }) {
                Text("Signer (Bitcoin)")
            }
            Spacer(Modifier.width(12.dp))
            Button(onClick = {
                val sig = resultText.lineSequence()
                    .firstOrNull { it.contains("DER (base64):") }
                    ?.substringAfter("DER (base64): ")
                    ?: resultText
                onCopy("Bitcoin DER signature", sig)
            }) { Text("Copier la signature") }
        }
        Text(resultText)
    }
}}



