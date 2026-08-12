# Agents CLI

Distribución pública oficial del CLI operativo de Agents Platform. No requiere Node.js, pnpm ni
acceso a paquetes privados.

## Instalación

Linux y macOS:

```bash
curl -fsSL https://agents.wizeit.co/install | sh
```

Windows PowerShell:

```powershell
irm https://agents.wizeit.co/install.ps1 | iex
```

Después de instalar:

```bash
agents --version
agents auth login
```

Plataformas publicadas:

- Linux x64 y arm64.
- macOS Apple Silicon.
- Windows x64.

## Actualización y rollback

El CLI sólo informa que existe una versión nueva; nunca se actualiza sin una orden explícita.

```bash
agents update --check
agents update
agents update --to VERSION_ANTERIOR
```

Cada versión se instala en un directorio separado. El launcher cambia sólo después de verificar el
artefacto descargado, por lo que `--to` permite volver a una versión estable publicada.

## Integridad del release

Un release estable contiene los cuatro binarios, instaladores, checksums y un manifiesto Ed25519
firmado. El manifiesto fija la versión, revisión fuente, URLs inmutables, tamaños y SHA-256. macOS
también exige Developer ID y notarización; Windows exige Authenticode. La publicación falla si
falta una plataforma o una firma.

No descargues ejecutables desde comentarios, forks ni enlaces alternativos. Los assets válidos se
publican exclusivamente en la sección **Releases** de este repositorio.
