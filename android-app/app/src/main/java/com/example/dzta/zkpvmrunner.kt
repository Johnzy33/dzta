package com.example.dzta

import android.content.Context
import android.system.virtualmachine.VirtualMachine
import android.system.virtualmachine.VirtualMachineConfig
import android.system.virtualmachine.VirtualMachineManager
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.OutputStreamWriter
import java.io.InputStreamReader
import android.os.ParcelFileDescriptor

class ZkpVmRunner(private val context: Context) {

    companion object {
        private const val TAG = "ZkpVmRunner"
        private const val VM_NAME = "dzta_zkp_vm"
        private const val PAYLOAD_ASSET_NAME = "dzta-protected-prover"
        private const val RAM_ALLOCATION_BYTES: Long = 256 * 1024 * 1024 // 256 MB
        private const val PROVER_VSOCK_PORT: Long = 5000 // Port configured in your Rust guest binary
    }

    suspend fun executeIsolatedProver(jsonInputs: String): Result<String> = withContext(Dispatchers.IO) {
        val vmManager = context.getSystemService(VirtualMachineManager::class.java)
            ?: return@withContext Result.failure(
                IllegalStateException("AVF (VirtualMachineManager) is not supported or accessible on this build.")
            )

        // Configure the Microdroid VM
        val config = VirtualMachineConfig.Builder(context)
            .setPayloadBinaryName(PAYLOAD_ASSET_NAME)
            .setProtectedVm(false) // Set to false for emulator/debug testing
            .setMemoryBytes(RAM_ALLOCATION_BYTES)
            .build()

        var vm: VirtualMachine? = null
        try {
            Log.d(TAG, "Provisioning pKVM container for ZK Prover execution...")

            // Pass the required VM name string as parameter 'p1'
            vm = vmManager.create(VM_NAME, config)

            // Start VM execution (method is run(), not start())
            vm.run()

//            Log.d(TAG, "Connecting to ZK Prover guest payload via VSOCK port $PROVER_VSOCK_PORT...")
//
//            // Connect to payload via VSOCK
//            val vsockStream = vm.connectVsock(PROVER_VSOCK_PORT)
//
//            Log.d(TAG, "Streaming input JSON into pVM boundary...")
//            OutputStreamWriter(vsockStream.outputStream, Charsets.UTF_8).use { writer ->
//                writer.write(jsonInputs)
//                writer.flush()
//            }
//
//            Log.d(TAG, "Awaiting Groth16 computation in protected RAM...")
//            val proofHex = InputStreamReader(vsockStream.inputStream, Charsets.UTF_8).buffered().use { reader ->
//                reader.readLine()
//            }

            Log.d(TAG, "Connecting to ZK Prover guest payload via VSOCK port $PROVER_VSOCK_PORT...")

            // vm.connectVsock returns a ParcelFileDescriptor
            val pfd: ParcelFileDescriptor = vm.connectVsock(PROVER_VSOCK_PORT.toLong())

            Log.d(TAG, "Streaming input JSON into pVM boundary...")
            // Wrap the PFD with AutoCloseOutputStream to stream data in
            ParcelFileDescriptor.AutoCloseOutputStream(pfd).use { outputStream ->
                OutputStreamWriter(outputStream, Charsets.UTF_8).use { writer ->
                    writer.write(jsonInputs)
                    writer.flush()
                }
            }

            Log.d(TAG, "Awaiting Groth16 computation in protected RAM...")
            // Re-open/wrap with AutoCloseInputStream to read response
            val proofHex = ParcelFileDescriptor.AutoCloseInputStream(pfd).use { inputStream ->
                InputStreamReader(inputStream, Charsets.UTF_8).buffered().use { reader ->
                    reader.readLine()
                }
            }

            if (proofHex.isNullOrBlank()) {
                Result.failure(IllegalStateException("pVM completed with empty output"))
            } else {
                Log.d(TAG, "✓ ZK Proof generated successfully inside pVM!")
                Result.success(proofHex.trim())
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error executing ZK Prover inside pVM boundary", e)
            Result.failure(e)
        } finally {
            try {
                vm?.stop()
                Log.d(TAG, "pVM container halted and isolated RAM released.")
            } catch (e: Exception) {
                Log.w(TAG, "Non-fatal error halting pVM", e)
            }
        }
    }
}