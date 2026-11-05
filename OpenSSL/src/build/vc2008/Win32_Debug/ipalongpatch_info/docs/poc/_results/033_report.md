# 033 / TAGGING / Append-Tag-String-ipalongpatch_20261102

Log file / ログファイル: `20261102_120949_033of033_TAGGING_Append-Tag-String-ipalongpatch_20261102.log` (in /home/user/work/deliver/ipalongpatch_info/logs/)

Verdict / 判定: **PASS**

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コード上の観察)

Not a vulnerability. Patch 033 is the version-tag patch required by the task: it appends the tag string `[ipalongpatch_20261102]` to `OPENSSL_VERSION_TEXT` in include/openssl/opensslv.h so that `openssl version` and `OpenSSL_version(OPENSSL_VERSION)` identify the patched build. `OPENSSL_VERSION_NUMBER` (0x1010117fL) and the shared-library version are deliberately left unchanged, so ABI/version checks of applications keep working.

脆弱性ではない。パッチ 033 はタスクが要求するバージョンタグのパッチであり、include/openssl/opensslv.h の `OPENSSL_VERSION_TEXT` にタグ文字列 `[ipalongpatch_20261102]` を付加して、`openssl version` と `OpenSSL_version(OPENSSL_VERSION)` がパッチ版ビルドを識別できるようにする。`OPENSSL_VERSION_NUMBER` (0x1010117fL) と共有ライブラリのバージョンは意図的に不変とし、アプリケーションの ABI/バージョン検査が引き続き機能するようにしている。

## PoC design / PoC の設計

`vercheck.c` prints the compile-time `OPENSSL_VERSION_NUMBER` / `OPENSSL_VERSION_TEXT` and the run-time `OpenSSL_version_num()` / `OpenSSL_version(OPENSSL_VERSION)`; it is built against the unpatched and the patched build. `openssl version` is run on both Linux builds and on the mingw64 (Windows x86_64) build of the patched tree under wine.

`vercheck.c` はコンパイル時の `OPENSSL_VERSION_NUMBER` / `OPENSSL_VERSION_TEXT` と実行時の `OpenSSL_version_num()` / `OpenSSL_version(OPENSSL_VERSION)` を表示し、未パッチ版・パッチ版の両ビルドに対してビルドする。`openssl version` を Linux の両ビルドと、パッチ版ツリーの mingw64 (Windows x86_64) ビルドで wine 上で実行する。

## Observed behaviour BEFORE the patch (evidence excerpts) / 修正前の挙動 (証拠の抜粋)

```
OPENSSL_VERSION_NUMBER = 0x1010117fL
OPENSSL_VERSION_TEXT   = "OpenSSL 1.1.1w  11 Sep 2023"
OpenSSL_version(OPENSSL_VERSION) = "OpenSSL 1.1.1w  11 Sep 2023"
```

## Observed behaviour AFTER the patch / 修正後の挙動

```
OPENSSL_VERSION_NUMBER = 0x1010117fL          (unchanged / 不変)
OPENSSL_VERSION_TEXT   = "OpenSSL 1.1.1w [ipalongpatch_20261102]  11 Sep 2023"
OpenSSL_version(OPENSSL_VERSION) = "OpenSSL 1.1.1w [ipalongpatch_20261102]  11 Sep 2023"
patched (mingw64 under wine): OpenSSL 1.1.1w [ipalongpatch_20261102]  11 Sep 2023
```

## Regression check / 回帰確認

The full `make test` of the tagged tree passed (159 recipe files, 2658 tests, PASS); the Windows build passed 194 tests under wine. Only the text macro changed.

タグ付与後ツリーの完全な `make test` は合格 (レシピ 159 ファイル、2658 テスト、PASS)。Windows ビルドは wine 上で 194 テスト合格。変更はテキストマクロのみ。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```bash
cd /home/user/work/poc/033_TAGGING
gcc -I/home/user/work/patched/build/include -I/home/user/work/patched/openssl-1.1.1w-ipalongpatch_20261102/include vercheck.c -L/home/user/work/patched/build -lcrypto -Wl,-rpath,/home/user/work/patched/build -o vercheck_patched && ./vercheck_patched
/home/user/work/patched/build/util/shlib_wrap.sh /home/user/work/patched/build/apps/openssl version
cd /home/user/work/patched/build-mingw64/apps && wine ./openssl.exe version
```

## Limitations / notes / 制約・注記

None. / 特になし。
