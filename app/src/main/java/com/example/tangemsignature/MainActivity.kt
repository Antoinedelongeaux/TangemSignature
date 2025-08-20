package com.example.tangemsignature

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                App()
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun App() {
    var count by remember { mutableStateOf(0) }
    var text by remember { mutableStateOf("") }
    var itemsList by remember { mutableStateOf(listOf<String>()) }

    Scaffold(
        topBar = { TopAppBar(title = { Text("Mon App Kotlin") }) },
        floatingActionButton = {
            FloatingActionButton(onClick = { count++ }) {
                Text("$count")
            }
        }
    ) { padding ->
        Column(
            Modifier
                .padding(padding)
                .padding(16.dp)
                .fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            OutlinedTextField(
                value = text,
                onValueChange = { text = it },
                label = { Text("Ajouter un élément") },
                modifier = Modifier.fillMaxWidth()
            )
            Button(
                onClick = {
                    if (text.isNotBlank()) {
                        itemsList = listOf(text.trim()) + itemsList
                        text = ""
                    }
                },
                modifier = Modifier.align(Alignment.End)
            ) { Text("Ajouter") }

            Divider()

            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(itemsList) { item ->
                    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                        Text(item, modifier = Modifier.padding(16.dp))
                    }
                }
            }
        }
    }
}
