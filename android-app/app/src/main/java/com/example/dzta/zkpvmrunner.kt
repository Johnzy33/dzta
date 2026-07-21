import android.content.Context
import android.system.virtualmachine.VirtualMachine
import android.system.virtualmachine.VirtualMachineConfig
import android.system.virtualmachine.VirtualMachineManager

class ZkpVmRunner(private val context: Context) {

    fun executeIsolatedProver(jsonInputs: String): String? {
        val vmManager = context.getSystemService(VirtualMachineManager::class.java) 
            ?: throw IllegalStateException("AVF is not supported on this device")

        // 1. Configure a Protected VM (pVM) with strict memory isolation enabled
        val config = VirtualMachineConfig.Builder(context)
            .setPayloadBinaryFilePath("dzta-protected-prover")
            .setProtectedVm(true) // <-- Instructs the pKVM hypervisor to lock down memory pages
            .setMemoryBytes(256 * 1024 * 1024) // Allocate 256MB for ZK crunches
            .build()

        val vm = vmManager.create(config)
        
        try {
            vm.start()

            // 2. Map standard streams straight over the VM boundary via Binder IPC
            val stdin = vm.openStdin()
            val stdout = vm.openStdout()

            // 3. Pipe the sensitive inputs down to the guest machine
            stdin.write(jsonInputs.toByteArray(Charsets.UTF_8))
            stdin.flush()
            stdin.close() // Signal EOF to the guest app

            // 4. Collect the resulting cryptographic string safely passed back out
            val proofHex = stdout.bufferedReader().use { it.readLine() }
            
            return proofHex
        } finally {
            // Ensure the pVM is completely destroyed and its physical RAM is zeroed out
            vm.stop()
        }
    }
}