<p align="center">
  <img src="../screenshot.png" alt="PureSnitch - firewall de aplicaciones para macOS de código abierto" width="800">
</p>

<p align="center">
  <a href="../README.md">English</a> |
  <a href="README.ar.md">العربية</a> |
  <b>Español</b> |
  <a href="README.ja.md">日本語</a>  |
  <a href="README.zh-Hans.md">简体中文</a> |
  <a href="README.zh-Hant.md">繁體中文</a>
</p>

<h1 align="center">PureSnitch</h1>

<p align="center">
  <b>Mira con quién habla tu Mac. Bloquea lo que no te gusta.</b><br>
  Firewall de aplicaciones de código abierto para macOS. Sin suscripción, sin telemetría, sin pop-ups de upselling.
</p>

## Instalar

```bash
brew tap momenbasel/puresnitch
brew install --cask puresnitch
```

O descarga el `.dmg` firmado y notarizado desde [Releases](https://github.com/momenbasel/puresnitch/releases/latest) y arrastra PureSnitch a `/Applications`.

## Por qué existe

Little Snitch es el estándar de oro para firewalls de aplicaciones en macOS y cuesta 59 USD por Mac. LuLu es gratis y excelente a nivel de proceso, pero el administrador de reglas es austero y no tiene mapa mundial ni gráfico de tráfico ni biblioteca de blocklists. El firewall integrado de macOS solo bloquea entrada - no hace nada con el tráfico saliente.

PureSnitch es la cuarta opción:

- **Misma interfaz que Little Snitch 6** - barra de menú, mapa mundial, gestor de reglas, alertas de conexión.
- **Código abierto bajo MIT** - léelo, fórkalo, audítalo.
- **Sin telemetría.** Sin SDKs de analítica, sin reportes de fallos.
- **Construido como una app nativa de Mac** - SwiftUI puro, no un puerto de otra plataforma.
- **Firmado y notarizado por Apple** - sin avisos de "desarrollador no verificado".

## Qué hace

- Monitor de Red con mapa mundial de cada conexión activa y ranking de procesos, dominios y países
- Gestor de Reglas completo al estilo Little Snitch - grupos, blocklists, búsqueda
- DNS sobre HTTPS a Cloudflare, Quad9, Google o cualquier endpoint DoH
- Proxy DNS local en `127.0.0.1:53` que intercepta cada consulta
- Bloqueo por dominio mediante 1Hosts, OISD, StevenBlack, HaGeZi
- Bloqueo por IP, CIDR y puerto a nivel kernel mediante el ancla `pfctl`
- Perfiles (default, home, public-wifi, lockdown) que cambian automáticamente con la red

## README completo en inglés

[README.md](../README.md)
