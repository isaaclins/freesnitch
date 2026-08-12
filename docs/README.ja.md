<p align="center">
  <img src="../screenshot.png" alt="PureSnitch - macOS 向けオープンソース アプリケーション ファイアウォール" width="800">
</p>

<p align="center">
  <a href="../README.md">English</a> |
  <a href="README.ar.md">العربية</a> |
  <a href="README.es.md">Español</a> |
  <b>日本語</b> |
  <a href="README.zh-Hans.md">简体中文</a> |
  <a href="README.zh-Hant.md">繁體中文</a>
</p>

<h1 align="center">PureSnitch</h1>

<p align="center">
  <b>Mac が何と通信しているかを確認し、信頼できないものをブロックします。</b><br>
  macOS 向けのオープンソース・アプリケーション・ファイアウォール。サブスクリプションなし、テレメトリーなし、アップセルなし。
</p>

## インストール

```bash
brew tap momenbasel/puresnitch
brew install --cask puresnitch
```

または [Releases](https://github.com/momenbasel/puresnitch/releases/latest) から署名・公証済みの `.dmg` をダウンロードし、PureSnitch を `/Applications` にドラッグします。

## なぜ作ったか

Little Snitch は macOS アプリケーション ファイアウォールのゴールド スタンダードですが、1 台あたり 59 ドルかかります。LuLu は無料でプロセス単位のカーネル レベルでは優秀ですが、ルール マネージャーが簡素で、世界地図もトラフィック グラフもブロックリスト ライブラリもありません。macOS 標準のファイアウォールは受信のみブロックします - 送信トラフィックには何もしません。

PureSnitch は 4 番目の選択肢です:

- **Little Snitch 6 と同じ UI パターン** - メニューバー、世界地図、ルール マネージャー、接続アラート
- **MIT ライセンスのオープンソース** - コードを読み、フォークし、監査できます
- **テレメトリーなし** - アナリティクス SDK もクラッシュ レポートも外部に送信しません
- **ネイティブの Mac アプリとして構築** - 真の SwiftUI、移植版ではありません
- **Apple による署名・公証済み** - "開発元未確認" の警告は出ません

## 主な機能

- アクティブな全接続を表示する世界地図、プロセス・ドメイン・国別のサマリー
- Little Snitch スタイルの完全なルール マネージャー - グループ、ブロックリスト、検索
- Cloudflare / Quad9 / Google または任意の DoH エンドポイントへの DNS over HTTPS
- `127.0.0.1:53` のローカル DNS プロキシで全クエリを傍受
- 1Hosts / OISD / StevenBlack / HaGeZi によるドメイン ブロック
- `pfctl` アンカーによる IP / CIDR / ポート単位のカーネル レベル ブロック
- プロファイル (default / home / public-wifi / lockdown) - ネットワーク変更に応じて自動切替

## 英語の完全な README

[README.md](../README.md)
