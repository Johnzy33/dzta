package com.example.dzta

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import java.security.SecureRandom

class MainActivity : ComponentActivity() {

    private lateinit var zkpRepository: ZkpRepository

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val vmRunner = ZkpVmRunner(applicationContext)
        zkpRepository = ZkpRepository(vmRunner)

        setContent {
            MaterialTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    ZkpProverScreen(zkpRepository)
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ZkpProverScreen(repository: ZkpRepository) {
    val scope = rememberCoroutineScope()
    var isComputing by remember { mutableStateOf(false) }
    var statusLog by remember { mutableStateOf("Ready to initiate pKVM execution...") }
    var generatedProofHex by remember { mutableStateOf("") }

    Scaffold(
        topBar = {
            TopAppBar(title = { Text("dZTA Isolated Prover (pKVM)") })
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text(
                text = "Hardware Enclave Execution",
                style = MaterialTheme.typography.titleLarge
            )
            Text(
                text = "Generates a Groth16 proof inside an isolated Android Protected VM (pKVM) where memory is encrypted and invisible to the host OS.",
                style = MaterialTheme.typography.bodyMedium
            )

            Button(
                onClick = {
                    scope.launch {
                        isComputing = true
                        statusLog = "Generating secure test witnesses & starting pVM..."
                        generatedProofHex = ""

                        // Generate a dummy 32-byte secret seed and its mathematical public parameter match:
                        // (seed * seed) + seed = publicParam
                        val secretSeed = ByteArray(32).apply { SecureRandom().nextBytes(this) }

                        // Pass mock public input parameter byte array
                        val publicParam = ByteArray(32).apply { SecureRandom().nextBytes(this) }

                        val result = repository.generateProof(secretSeed, publicParam)

                        isComputing = false
                        result.fold(
                            onSuccess = { hex ->
                                statusLog = "✓ Proof generated inside pVM boundary!"
                                generatedProofHex = hex
                            },
                            onFailure = { err ->
                                statusLog = "✗ Prover execution failed: ${err.localizedMessage}"
                            }
                        )
                    }
                },
                enabled = !isComputing,
                modifier = Modifier.fillMaxWidth()
            ) {
                if (isComputing) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(20.dp),
                        color = MaterialTheme.colorScheme.onPrimary,
                        strokeWidth = 2.dp
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Executing inside pVM...")
                } else {
                    Text("Run Groth16 Prover in pVM")
                }
            }

            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                )
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "System Status",
                        style = MaterialTheme.typography.labelLarge
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = statusLog,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }

            if (generatedProofHex.isNotEmpty()) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.primaryContainer
                    )
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            text = "Generated Proof (Hex Output)",
                            style = MaterialTheme.typography.labelLarge
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = generatedProofHex,
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                }
            }
        }
    }
}