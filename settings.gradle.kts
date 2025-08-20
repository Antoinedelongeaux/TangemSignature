// settings.gradle.kts

pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        mavenLocal()                 // ← prend d'abord ce qui a été publié en local
        google()
        mavenCentral()
        maven(url = "https://jitpack.io")
    }
}

rootProject.name = "TangemSignature"
include(":app")

// Pas de includeBuild ici (on utilise mavenLocal au lieu d’un composite build)
