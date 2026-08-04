package com.example.dzta

import org.json.JSONArray
import org.json.JSONObject

data class ZkpInputPayload(
    val secretSeed: ByteArray,  // 32-byte secret witness
    val publicParam: ByteArray // Matching public parameter
) {
    fun toJsonString(): String {
        return JSONObject().apply {
            put("secret_seed", JSONArray(secretSeed.map { it.toInt() and 0xFF }))
            put("public_param", JSONArray(publicParam.map { it.toInt() and 0xFF }))
        }.toString()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ZkpInputPayload

        if (!secretSeed.contentEquals(other.secretSeed)) return false
        if (!publicParam.contentEquals(other.publicParam)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = secretSeed.contentHashCode()
        result = 31 * result + publicParam.contentHashCode()
        return result
    }
}

class ZkpRepository(private val vmRunner: ZkpVmRunner) {

    suspend fun generateProof(
        secretSeedBytes: ByteArray,
        publicParamBytes: ByteArray
    ): Result<String> {
        require(secretSeedBytes.size == 32) { "Secret seed must be exactly 32 bytes" }

        val payload = ZkpInputPayload(
            secretSeed = secretSeedBytes,
            publicParam = publicParamBytes
        )

        return vmRunner.executeIsolatedProver(payload.toJsonString())
    }
}