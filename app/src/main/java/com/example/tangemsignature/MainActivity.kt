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
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.tangem.TangemSdk
import com.tangem.common.CompletionResult
import com.tangem.common.card.EllipticCurve
import com.tangem.crypto.hdWallet.DerivationPath
import com.tangem.common.extensions.toHexString
import com.tangem.common.core.CardSession
//import com.tangem.common.core.CardSession
import com.tangem.operations.sign.SignHashCommand
import com.tangem.operations.sign.SignHashResponse
import com.tangem.operations.derivation.DeriveWalletPublicKeyTask as DeriveWalletPublicKeyCommand
import com.tangem.sdk.extensions.init
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicBoolean

class MainActivity : ComponentActivity() {

    private lateinit var sdk: TangemSdk
    private val mainHandler by lazy { Handler(Looper.getMainLooper()) }
    private val isWorking = AtomicBoolean(false)

    // Adresse cible
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

    /** Scan → trouve chemin BIP84 qui correspond à l’adresse → signe */
    private fun signForAddress(message: String, address: String, onResult: (String) -> Unit) {
        if (!isWorking.compareAndSet(false, true)) {
            onResult("⏳ Une opération est déjà en cours…")
            return
        }

        val digest = bitcoinMessageDigest(message)
        val dec = decodeBech32P2WPKH(address)
        if (dec == null) {
            finishWork { onResult("Adresse cible invalide (attendue: bech32 P2WPKH v0).") }
            return
        }

        onResult("🔍 Recherche du chemin BIP84…")

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

                    // ✅ Utilise un callback lambda, plus CompletionCallback
                    sdk.startSessionWithRunnable(
                        object : com.tangem.common.core.CardSessionRunnable<Unit> {
                            override fun run(
                                session: com.tangem.common.core.CardSession,
                                callback: (CompletionResult<Unit>) -> Unit
                            ) {
                                tryFindBip84PathForAddressInActiveSession(
                                    session = session,
                                    cardId = cardId,
                                    masterWalletPub = masterWalletPub,
                                    hrp = dec.hrp,
                                    wantedProgram20 = dec.program20,
                                    onProgress = { attempt, path ->
                                        mainHandler.post {
                                            onResult("🔍 Recherche BIP84… essai $attempt\nDernier chemin: $path")
                                        }
                                    },
                                    done = { foundPath, derivedPub, tried ->
                                    if (foundPath == null || derivedPub == null) {
                                        mainHandler.post {
                                            finishWork {
                                                onResult("❌ Aucun chemin BIP84 trouvé.\nAdresse cible: $address")
                                            }
                                            callback(CompletionResult.Success(Unit))
                                        }
                                        return@tryFindBip84PathForAddressInActiveSession
                                    }

                                    session.request(
                                        SignHashCommand(
                                            hash = digest,
                                            walletPublicKey = masterWalletPub,
                                            derivationPath = foundPath,
                                        )
                                    ) { signResult ->
                                        when (signResult) {
                                            is CompletionResult.Success -> {
                                                val rawSig = signResult.data.signature
                                                if (rawSig.size != 64) {
                                                    mainHandler.post {
                                                        finishWork { onResult("Signature inattendue: ${signResult.data}") }
                                                        callback(CompletionResult.Success(Unit))
                                                    }
                                                    return@request
                                                }

                                                val der = raw64ToDerLowS(rawSig)
                                                val base64 = Base64.encodeToString(der, Base64.NO_WRAP)
                                                val derivedAddr = p2wpkhAddress(dec.hrp, compressIfNeeded(derivedPub))

                                                mainHandler.post {
                                                    finishWork {
                                                        onResult(
                                                            """
                                        ✅ Signature Bitcoin
                                        • Chemin: $foundPath
                                        • Adresse dérivée: $derivedAddr
                                        • PubKey dérivée: ${compressIfNeeded(derivedPub).toHexString()}
                                        • Signature DER (base64): $base64
                                        """.trimIndent()
                                                        )
                                                    }
                                                    callback(CompletionResult.Success(Unit))
                                                }
                                            }
                                            is CompletionResult.Failure -> {
                                                mainHandler.post {
                                                    finishWork { onResult("Erreur signature: ${signResult.error}") }
                                                    callback(CompletionResult.Success(Unit))
                                                }
                                            }
                                        }
                                    }
                                    }
                                )
                            },
                            initialMessage = null,
                            cardId = cardId
                        ) { sessionResult: CompletionResult<Unit> ->
                        // ✅ callback final obligatoire
                        when (sessionResult) {
                            is CompletionResult.Success -> {
                                // OK → rien de spécial à faire
                            }
                            is CompletionResult.Failure -> {
                                // Tu peux logguer ici si nécessaire
                            }
                        }
                    }


                }

                is CompletionResult.Failure<*> -> {
                    finishWork { onResult("Erreur scan: ${scanResult.error}") }
                }
            }
        }
    }



    /** Recherche du chemin BIP84 */
    /** Recherche d’un chemin BIP84 qui correspond exactement à l’adresse P2WPKH donnée. */

    private fun tryFindBip84PathForAddressInActiveSession(
        session: CardSession,
        cardId: String,
        masterWalletPub: ByteArray,
        hrp: String,
        wantedProgram20: ByteArray,
        maxAccount: Int = 2,
        maxIndex: Int = 20,
        onProgress: ((Int, String) -> Unit)? = null,
        done: (DerivationPath?, ByteArray?, List<String>) -> Unit,
    ) {
        val tried = mutableListOf<String>()

        // Déduit le coinType à partir du HRP : bc -> 0, tb -> 1
        val coinType = when (hrp) {
            "tb" -> 1
            else -> 0
        }

        var attempts = 0
        val maxAttempts = maxAccount * 2 * (maxIndex + 1)

        fun extractPub(data: Any?): ByteArray? = when (data) {
            is ByteArray -> data
            else -> try {
                val f = data?.javaClass?.getDeclaredField("publicKey")
                f?.isAccessible = true
                f?.get(data) as? ByteArray
            } catch (_: Throwable) { null }
        }

        fun matches(pub: ByteArray?): Boolean {
            if (pub == null) return false
            val prog = hash160(compressIfNeeded(pub))
            return prog.contentEquals(wantedProgram20)
        }

        // Itération asynchrone : on enchaîne les derives dans la session courante
        fun next(account: Int, change: Int, index: Int) {
            if (account >= maxAccount || attempts >= maxAttempts) {
                done(null, null, tried)
                return
            }
            if (change > 1) {
                next(account + 1, 0, 0)
                return
            }
            if (index > maxIndex) {
                next(account, change + 1, 0)
                return
            }

            val path = DerivationPath("m/84'/$coinType'/${account}'/$change/$index")
            tried += path.toString()
            attempts++
            onProgress?.invoke(attempts, path.toString())

            // IMPORTANT : cet appel est fait ALORS QUE la session est déjà ouverte ;
            // le SDK réutilise la session → pas de nouveau scan / code.
            session.request(
                DeriveWalletPublicKeyCommand(
                    walletPublicKey = masterWalletPub,
                    derivationPath = path,
                )
            ) { res: CompletionResult<*> ->
                val derivedPub = when (res) {
                    is CompletionResult.Success<*> -> extractPub(res.data)
                    else -> null
                }

                if (matches(derivedPub)) {
                    done(path, derivedPub, tried)
                } else {
                    // enchaîne
                    next(account, change, index + 1)
                }
            }
        }

        // démarre la recherche
        next(0, 0, 0)
    }




    private fun finishWork(action: () -> Unit) {
        runOnUiThread { try { action() } finally { isWorking.set(false) } }
    }

    // --- helpers crypto (inchangés) ---
    private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)
    private fun ripemd160(b: ByteArray) = MessageDigest.getInstance("RIPEMD160").digest(b)
    private fun hash160(b: ByteArray) = ripemd160(sha256(b))

    private fun compressIfNeeded(pub: ByteArray): ByteArray {
        if (pub.size == 33) return pub
        if (pub.size != 65) return pub
        val y = BigInteger(1, pub.copyOfRange(33, 65))
        val prefix: Byte = if (y.and(BigInteger.ONE) == BigInteger.ZERO) 0x02 else 0x03
        val x = pub.copyOfRange(1, 33)
        return byteArrayOf(prefix) + x
    }

    private fun varInt(n: Long): ByteArray = when {
        n < 0xFD -> byteArrayOf(n.toByte())
        n <= 0xFFFF -> byteArrayOf(0xFD.toByte()) +
                ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort(n.toShort()).array()
        n <= 0xFFFF_FFFFL -> byteArrayOf(0xFE.toByte()) +
                ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(n.toInt()).array()
        else -> byteArrayOf(0xFF.toByte()) +
                ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(n).array()
    }

    private fun bitcoinMessageDigest(message: String): ByteArray {
        val prefix = "Bitcoin Signed Message:\n".toByteArray()
        val msg = message.toByteArray()
        val baos = ByteArrayOutputStream()
        baos.write(varInt(prefix.size.toLong()))
        baos.write(prefix)
        baos.write(varInt(msg.size.toLong()))
        baos.write(msg)
        return sha256(sha256(baos.toByteArray()))
    }

    private fun raw64ToDerLowS(raw: ByteArray): ByteArray {
        require(raw.size == 64)
        val r = BigInteger(1, raw.copyOfRange(0, 32))
        val s = BigInteger(1, raw.copyOfRange(32, 64))
        val n = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
        val halfN = n.shiftRight(1)
        val sLow = if (s > halfN) n.subtract(s) else s
        fun derInt(i: BigInteger): ByteArray {
            var b = i.toByteArray()
            if (b.size > 1 && b[0] == 0.toByte() && (b[1].toInt() and 0x80) == 0) {
                b = b.copyOfRange(1, b.size)
            }
            if ((b[0].toInt() and 0x80) != 0) b = byteArrayOf(0x00) + b
            return byteArrayOf(0x02) + byteArrayOf(b.size.toByte()) + b
        }
        val derR = derInt(r)
        val derS = derInt(sLow)
        val seq = derR + derS
        return byteArrayOf(0x30) + byteArrayOf(seq.size.toByte()) + seq
    }

    // --- Bech32 helpers (inchangés) ---
    private data class Bech32Decoded(val hrp: String, val program20: ByteArray)
    // -------- Bech32 (encode + decode) --------


    private fun p2wpkhAddress(hrp: String, pubCompressed: ByteArray): String {
        val program = hash160(pubCompressed)            // 20 bytes
        return bech32EncodeWitnessV0(hrp, program)
    }

    private fun bech32EncodeWitnessV0(hrp: String, program: ByteArray): String {
        val converted = convertBits(program.map { it.toInt() and 0xFF }.toIntArray(), 8, 5, true)
            ?: return ""
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

    private val charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    private val charsetRev = charset.withIndex().associate { it.value to it.index }

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




}

private fun CardSession.request(
    signHashCommand: SignHashCommand,
    function: Any
) {
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
}
