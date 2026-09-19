# パスまね

個人利用向けのオフライン・パスワード管理Androidアプリです。

## クラウドでAPKを作成する

このプロジェクトはGitHub ActionsでデバッグAPKを作成します。ローカルにAndroid Studio、Android SDK、Gradleをインストールする必要はありません。

1. GitHubで空のリポジトリを作成します。
2. このフォルダをGitリポジトリとして初期化し、GitHubへプッシュします。
3. GitHubのリポジトリ画面で **Actions** を開き、`Build Android APK` を実行します。
4. 完了した実行結果の **Artifacts** から `passmane-debug-apk` をダウンロードします。

APKのファイル名は `app-debug.apk` です。これは動作確認用のデバッグAPKであり、配布用の署名済みリリースAPKではありません。