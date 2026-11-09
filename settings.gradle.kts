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
        google()
        mavenCentral()
    }
}

rootProject.name = "Detect-Any"

// 模块清单与 design.md D1 保持一致
include(":app")

include(":core:model")
include(":core:engine")
include(":core:rules")
include(":core:native-platform")

include(":collectors:fs-probe")
include(":collectors:properties")
include(":collectors:endpoints")
include(":collectors:app-fingerprint")
include(":collectors:memory-map")
include(":collectors:code-integrity")
include(":collectors:behavior-probe")
include(":collectors:instrument-probe")
include(":collectors:virtual-env")
include(":collectors:behavior-check")
include(":collectors:screen-share")

include(":feature:attestation")
include(":feature:report")

include(":data:signature")

include(":compat:platform")

include(":selfguard")
