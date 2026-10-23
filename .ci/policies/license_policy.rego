package main

import future.keywords.in

allowed_licenses := {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", 
    "ISC", "Zlib", "Unlicense", "CC0-1.0", "BSL-1.0", "0BSD",
    "MIT OR Apache-2.0", "Apache-2.0 OR MIT", "Apache-2.0 WITH LLVM-exception",
    "Apache-2.0 OR BSL-1.0", "MIT OR Unlicense", "BSD-3-Clause OR MIT"
}

review_licenses := {
    "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later",
    "MPL-2.0", "EPL-1.0", "EPL-2.0", "CDDL-1.0", 
    "GPL-2.0-with-classpath-exception", "CC-BY-4.0"
}

forbidden_licenses := {
    "AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0", "OSL-3.0",
    "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later",
    "BUSL-1.1", "Commons-Clause", "RSALv2", "ELv2",
    "CC-BY-NC-4.0", "WTFPL", "JSON", "NOASSERTION", "NONE"
}

approved_exceptions := {}

# Función auxiliar para extraer el ID, Nombre o Expresión SPDX
get_license(comp) = lic {
    lic := comp.licenses[_].license.id
} else = lic {
    lic := comp.licenses[_].license.name
} else = lic {
    lic := comp.licenses[_].expression
}

# REGLA BLOQUEANTE 1: Categoría ROJA
deny[msg] {
    comp := input.components[_]
    comp.type == "library"
    not comp.purl in approved_exceptions
    lic := get_license(comp)
    lic in forbidden_licenses
    msg := sprintf("[ROJO - BLOQUEADO] El paquete '%s' (%s) utiliza una licencia prohibida: %s", [comp.name, comp.version, lic])
}

# REGLA DE ADVERTENCIA: Categoría AMARILLA
warn[msg] {
    comp := input.components[_]
    comp.type == "library"
    not comp.purl in approved_exceptions
    lic := get_license(comp)
    lic in review_licenses
    msg := sprintf("[AMARILLO - REVISIÓN REQUERIDA] El paquete '%s' (%s) usa licencia '%s'.", [comp.name, comp.version, lic])
}

# REGLA DE ADVERTENCIA: Metadatos de licencia ausentes en lockfile local
warn[msg] {
    comp := input.components[_]
    comp.type == "library"
    not comp.purl in approved_exceptions
    not comp.licenses
    msg := sprintf("[AVISO - METADATO LOCAL AUSENTE] '%s' (%s) solo figura en el lockfile sin licencia descargada en caché.", [comp.name, comp.version])
}
