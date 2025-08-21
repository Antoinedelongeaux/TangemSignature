package com.example.tangemsignature

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Base64
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.annotation.RequiresApi
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.tangem.TangemSdk
import com.tangem.common.CompletionResult
import com.tangem.common.card.EllipticCurve
import com.tangem.common.core.TangemSdkError
import com.tangem.crypto.hdWallet.DerivationPath
import com.tangem.operations.derivation.DeriveMultipleWalletPublicKeysTask
import com.tangem.operations.derivation.DeriveWalletPublicKeyTask
import com.tangem.operations.sign.SignHashCommand
import com.tangem.sdk.extensions.init
import com.tangem.common.extensions.ByteArrayKey
import org.bitcoinj.core.ECKey
import org.bitcoinj.core.LegacyAddress
import org.bitcoinj.core.SegwitAddress
import org.bitcoinj.core.Utils
import org.bitcoinj.core.Sha256Hash
import org.bitcoinj.params.MainNetParams
import org.bitcoinj.script.ScriptBuilder
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.security.KeyFactory
import java.util.concurrent.atomic.AtomicBoolean

class MainActivity : ComponentActivity() {

    private lateinit var sdk: TangemSdk
    private val mainHandler by lazy { Handler(Looper.getMainLooper()) }
    private val isWorking = AtomicBoolean(false)

    private val resultState = mutableStateOf("")
    private var knownPath: DerivationPath? = null

    private val targetAddress = "bc1q4fj5w4vunuar7ep76yxa7vchn3xryrcgu8jnld"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        sdk = TangemSdk.init(this, com.tangem.common.core.Config())

        setContent {
            MaterialTheme {
                SignScreen(
                    initialMessage = "",
                    targetAddr = targetAddress,
                    resultState = resultState,
                    onSign = { msg, addr -> signForAddress(msg, addr) },
                    onCopy = { label, text -> copyToClipboard(label, text) }
                )
            }
        }

        initializeWallet()
    }

    @RequiresApi(Build.VERSION_CODES.HONEYCOMB)
    private fun copyToClipboard(label: String, text: String) {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.HONEYCOMB) {
            cm.setPrimaryClip(ClipData.newPlainText(label, text))
        }
    }

    private fun initializeWallet() {
        sdk.scanCard { scanResult ->
            when (scanResult) {
                is CompletionResult.Success<*> -> {
                    val card = scanResult.data as? com.tangem.common.card.Card
                    val wallet = card?.wallets?.firstOrNull { it.curve == EllipticCurve.Secp256k1 }
                    if (card == null || wallet == null) {
                        resultState.value = "❌ Aucun wallet secp256k1 trouvé."
                        return@scanCard
                    }

                    val cardId = card.cardId!!
                    val masterWalletPub = wallet.publicKey

                    val paths = listOf(
                        DerivationPath("m/44'/0'/0'/0/0"),
                        DerivationPath("m/49'/0'/0'/0/0"),
                        DerivationPath("m/84'/0'/0'/0/0"),
                    )
                    deriveInitial(cardId, masterWalletPub, paths)
                }
                is CompletionResult.Failure -> {
                    resultState.value = "Erreur scan initial: ${scanResult.error}"
                }
            }
        }
    }

    private fun deriveInitial(
        cardId: String,
        masterWalletPub: ByteArray,
        paths: List<DerivationPath>,
        retries: Int = 1,
    ) {
        val derivationMap = mapOf(ByteArrayKey(masterWalletPub) to paths)
        sdk.startSessionWithRunnable(
            DeriveMultipleWalletPublicKeysTask(derivationMap),
            initialMessage = null,
            cardId = cardId,
        ) { deriveResult ->
            when (deriveResult) {
                is CompletionResult.Success -> {
                    val params = MainNetParams.get()
                    val entries = deriveResult.data.entries[ByteArrayKey(masterWalletPub)]
                    val sb = StringBuilder()
                    var found: DerivationPath? = null
                    entries?.forEach { (path, extKey) ->
                        val pub = compressIfNeeded(extKey.publicKey)
                        val key = ECKey.fromPublicOnly(pub)
                        val addr = when {
                            path.toString().startsWith("m/44'") ->
                                LegacyAddress.fromKey(params, key).toString()
                            path.toString().startsWith("m/49'") -> {
                                val redeem = ScriptBuilder.createP2WPKHOutputScript(key)
                                val scriptHash = Utils.sha256hash160(redeem.program)
                                LegacyAddress.fromScriptHash(params, scriptHash).toString()
                            }
                            else -> SegwitAddress.fromKey(params, key).toString()
                        }
                        sb.append("Chemin $path → $addr\n")
                        if (addr == targetAddress) {
                            found = path
                        }
                    }
                    knownPath = found
                    resultState.value = if (found != null) {
                        sb.append("\n✅ Chemin correspondant: $found").toString()
                    } else {
                        sb.append("\n⚠️ Aucun chemin ne correspond à $targetAddress").toString()
                    }
                }
                is CompletionResult.Failure -> {
                    if (retries > 0 && deriveResult.error is TangemSdkError.Busy) {
                        mainHandler.postDelayed({
                            deriveInitial(cardId, masterWalletPub, paths, retries - 1)
                        }, 500)
                    } else {
                        resultState.value = "Erreur dérivation initiale: ${deriveResult.error}"
                    }
                }
            }
        }
    }

    private fun signForAddress(message: String, address: String) {
        if (!isWorking.compareAndSet(false, true)) {
            resultState.value = "⏳ Une opération est déjà en cours…"
            return
        }

        val digest = bitcoinMessageDigest(message)
        val dec = decodeBech32P2WPKH(address)
        if (dec == null) {
            finishWork { resultState.value = "Adresse cible invalide." }
            return
        }

        sdk.scanCard { scanResult ->
            when (scanResult) {
                is CompletionResult.Success<*> -> {
                    val card = scanResult.data as? com.tangem.common.card.Card
                    val wallet = card?.wallets?.firstOrNull { it.curve == EllipticCurve.Secp256k1 }
                    if (card == null || wallet == null) {
                        finishWork { resultState.value = "❌ Aucun wallet secp256k1 trouvé." }
                        return@scanCard
                    }

                    val cardId = card.cardId!!
                    val masterWalletPub = wallet.publicKey
                    val presetPath = knownPath
                    if (presetPath != null) {
                        fun deriveAndSign(retries: Int = 1) {
                            sdk.startSessionWithRunnable(
                                DeriveWalletPublicKeyTask(masterWalletPub, presetPath),
                                initialMessage = null,
                                cardId = cardId,
                            ) { deriveResult ->
                                when (deriveResult) {
                                    is CompletionResult.Success -> {
                                        val derivedPub = deriveResult.data.publicKey
                                        val compressedPub = compressIfNeeded(derivedPub)
                                        val derivedAddr = p2wpkhAddress(dec.hrp, compressedPub)
                                        if (derivedAddr == address) {
                                            fun sign(retriesSign: Int = 1) {
                                                sdk.startSessionWithRunnable(
                                                    SignHashCommand(
                                                        hash = digest,
                                                        walletPublicKey = masterWalletPub,
                                                        derivationPath = presetPath,
                                                    ),
                                                    initialMessage = null,
                                                    cardId = cardId,
                                                ) { signResult ->
                                                    when (signResult) {
                                                        is CompletionResult.Success -> {
                                                            val rawSig = signResult.data.signature
                                                            val base64 = rawSigToMessageBase64(
                                                                rawSig,
                                                                digest,
                                                                compressedPub
                                                            )
                                                            mainHandler.post {
                                                                finishWork {
                                                                    resultState.value = """✅ Chemin trouvé: $presetPath
Adresse: $derivedAddr
Signature (base64): $base64""".trimIndent()
                                                                }
                                                            }
                                                        }
                                                        is CompletionResult.Failure -> {
                                                            if (retriesSign > 0 && signResult.error is TangemSdkError.Busy) {
                                                                mainHandler.postDelayed({ sign(retriesSign - 1) }, 500)
                                                            } else {
                                                                finishWork { resultState.value = "⚠️ Erreur signature: ${signResult.error}" }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            sign()
                                        } else {
                                            finishWork { resultState.value = "⚠️ Le chemin enregistré ne correspond pas à l'adresse fournie." }
                                        }
                                    }
                                    is CompletionResult.Failure -> {
                                        if (retries > 0 && deriveResult.error is TangemSdkError.Busy) {
                                            mainHandler.postDelayed({ deriveAndSign(retries - 1) }, 500)
                                        } else {
                                            finishWork { resultState.value = "⚠️ Erreur dérivation: ${deriveResult.error}" }
                                        }
                                    }
                                }
                            }
                        }
                        deriveAndSign()
                    } else {
                        val derivationPaths = buildList {
                            for (branch in 0..1) {
                                for (index in 0 until 20) {
                                    add(DerivationPath("m/84'/0'/0'/$branch/$index"))
                                }
                            }
                        }

                        fun tryNextPath(i: Int) {
                            if (i >= derivationPaths.size) {
                                finishWork { resultState.value = "❌ Aucun chemin BIP84 testé n’a correspondu à $address" }
                                return
                            }

                            val path = derivationPaths[i]

                            sdk.startSessionWithRunnable(
                                DeriveWalletPublicKeyTask(masterWalletPub, path),
                                initialMessage = null,
                                cardId = cardId,
                            ) { deriveResult ->
                                when (deriveResult) {
                                    is CompletionResult.Success -> {
                                        val derivedPub = deriveResult.data.publicKey
                                        val compressedPub = compressIfNeeded(derivedPub)
                                        val derivedAddr = p2wpkhAddress(dec.hrp, compressedPub)

                                        mainHandler.post {
                                            resultState.value = "🔎 Test chemin $path → adresse dérivée $derivedAddr"
                                        }

                                        if (derivedAddr == address) {
                                            sdk.startSessionWithRunnable(
                                                SignHashCommand(
                                                    hash = digest,
                                                    walletPublicKey = masterWalletPub,
                                                    derivationPath = path,
                                                ),
                                                initialMessage = null,
                                                cardId = cardId,
                                            ) { signResult ->
                                                when (signResult) {
                                                    is CompletionResult.Success -> {
                                                        val rawSig = signResult.data.signature
                                                        val base64 = rawSigToMessageBase64(
                                                            rawSig,
                                                            digest,
                                                            compressedPub
                                                        )
                                                        mainHandler.post {
                                                            finishWork {
                                                                resultState.value = """✅ Chemin trouvé: $path
Adresse: $derivedAddr
Signature (base64): $base64""".trimIndent()
                                                            }
                                                        }
                                                    }
                                                    is CompletionResult.Failure -> {
                                                        finishWork { resultState.value = "⚠️ Erreur signature: ${signResult.error}" }
                                                    }
                                                }
                                            }
                                        } else {
                                            tryNextPath(i + 1)
                                        }
                                    }
                                    is CompletionResult.Failure -> {
                                        mainHandler.post {
                                            resultState.value = "⚠️ Erreur dérivation avec chemin $path: ${deriveResult.error}"
                                        }
                                        tryNextPath(i + 1)
                                    }
                                }
                            }
                        }

                        tryNextPath(0)
                    }
                }
                is CompletionResult.Failure -> {
                    finishWork { resultState.value = "Erreur scan: ${scanResult.error}" }
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
        // Follow the "Bitcoin Signed Message" standard and always use byte counts
        val prefixBytes = prefix.toByteArray()
        val messageBytes = message.toByteArray()
        data.write(varInt(prefixBytes.size))
        data.write(prefixBytes)
        data.write(varInt(messageBytes.size))
        data.write(messageBytes)
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
        // Tangem may return an uncompressed 65-byte key starting with 0x04.
        // Instead of relying on JCE key parsing (which expects X.509 format),
        // we manually compress the raw coordinates so that the resulting
        // key can be used reliably for address derivation and signature checks.
        if (pubKey.size == 33) return pubKey // déjà compressé

        require(pubKey.size == 65 && pubKey[0] == 0x04.toByte()) {
            "Invalid uncompressed public key"
        }

        val x = pubKey.copyOfRange(1, 33)
        val y = pubKey.copyOfRange(33, 65)
        val prefix: Byte = if ((y.last().toInt() and 1) == 1) 0x03 else 0x02
        return byteArrayOf(prefix) + x
    }

    private fun rawSigToMessageBase64(sig: ByteArray, digest: ByteArray, pubCompressed: ByteArray): String {
        if (sig.size != 64) return Base64.encodeToString(sig, Base64.NO_WRAP)
        val r = BigInteger(1, sig.copyOfRange(0, 32))
        val s = BigInteger(1, sig.copyOfRange(32, 64))
        val signature = ECKey.ECDSASignature(r, s).toCanonicalised()
        val hash = Sha256Hash.wrap(digest)

        var recId = -1
        for (i in 0..3) {
            val key = ECKey.recoverFromSignature(i, signature, hash, true)
            if (key != null && key.pubKey.contentEquals(pubCompressed)) {
                recId = i
                break
            }
        }
        require(recId != -1) { "Cannot recover key from signature" }

        val header = (27 + recId + 4).toByte()
        val out = ByteArray(65)
        out[0] = header
        System.arraycopy(Utils.bigIntegerToBytes(signature.r, 32), 0, out, 1, 32)
        System.arraycopy(Utils.bigIntegerToBytes(signature.s, 32), 0, out, 33, 32)
        return Base64.encodeToString(out, Base64.NO_WRAP)
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
    resultState: MutableState<String>,
    onSign: (String, String) -> Unit,
    onCopy: (String, String) -> Unit
) {
    var message by remember { mutableStateOf(initialMessage) }
    var address by remember { mutableStateOf(targetAddr) }
    var resultText by resultState

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
            Button(onClick = { onSign(message, address) }) {
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



