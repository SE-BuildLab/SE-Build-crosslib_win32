###### ============================================================
# IPALongPatch [033/033] TAGGING - Append the IPALongPatch tag string to OPENSSL_VERSION_TEXT (version tagging, not a vulnerability)
# IPALongPatch [033/033] TAGGING - OPENSSL_VERSION_TEXT への IPALongPatch タグ文字列の追記 (バージョンタグ付け、脆弱性ではない)

## 0. Resolved vulnerability / 解決した脆弱性

- **Identifier / 識別子:** `TAGGING`  (other IDs / 他の ID: not a vulnerability; IPALongPatch rule [PER_OSS_TAGGING_RULES:VER261102])
- **Patch / パッチ:** `Append-Tag-String-ipalongpatch_20261102` (033 of 033) - `ipalongpatch_info/patch_files_for_each_cve/openssl-1.1.1w_ipalongpatch_033of033_TAGGING_Append-Tag-String-ipalongpatch_20261102.patch`
- **Summary (EN):** So that a patched build can be recognised externally, the human readable version text is changed from 'OpenSSL 1.1.1w  11 Sep 2023' to 'OpenSSL 1.1.1w [ipalongpatch_20261102]  11 Sep 2023'. OPENSSL_VERSION_NUMBER (0x1010117fL), the major/minor/patch numbers and SHLIB_VERSION_NUMBER are intentionally unchanged so that version checks keep working.
- **概要 (JA):** パッチ済みビルドを外形的に識別できるように、人間向けのバージョン文字列を 'OpenSSL 1.1.1w  11 Sep 2023' から 'OpenSSL 1.1.1w [ipalongpatch_20261102]  11 Sep 2023' に変更する。OPENSSL_VERSION_NUMBER (0x1010117fL)、major/minor/patch の各番号、SHLIB_VERSION_NUMBER は意図的に不変とし、バージョン検査が壊れないようにする。
- **Status:** applied to openssl-1.1.1w-ipalongpatch_20261102 and verified (PASS). / **状態:** openssl-1.1.1w-ipalongpatch_20261102 に適用し検証済み (合格)。

## 1. Heading / 見出し

- **Document generated / 文書生成日時:** 2026/11/02 16:49:32 (JST)
- **Title (verbatim) / 標題 (原文どおり):** `DNNT 261102_EEHXW5 IPALongPatch openssl-1.1.1w-ipalongpatch_20261102 OpenSSL_1.1.1f_From_Ubuntu`
- **Task (EN):** Back-port the security fixes that Canonical applied to Ubuntu 20.04's openssl 1.1.1f (1.1.1f-1ubuntu2.24+esm6) after the last public OpenSSL 1.1.1 release (1.1.1w, 2023-09-11) onto OpenSSL 1.1.1w, producing openssl-1.1.1w-ipalongpatch_20261102-river_lantern.tar.gz: a complete, buildable source tree with per-vulnerability patches, a consolidated patch, verification logs and this documentation.  This file documents item 033 (TAGGING).
- **タスク (JA):** Canonical が Ubuntu 20.04 の openssl 1.1.1f (1.1.1f-1ubuntu2.24+esm6) に対して、OpenSSL 1.1.1 最後の公開版 (1.1.1w、2023-09-11) より後に適用したセキュリティ修正を OpenSSL 1.1.1w へ移植し、openssl-1.1.1w-ipalongpatch_20261102-river_lantern.tar.gz (単独でビルド可能な完全なソースツリー、脆弱性別パッチ、集約パッチ、検証ログ、本ドキュメント) を作成する。本ファイルは項目 033 (TAGGING) を記録する。
- **Change summary (EN):** include/openssl/opensslv.h: OPENSSL_VERSION_TEXT -> "OpenSSL 1.1.1w [ipalongpatch_20261102]  11 Sep 2023"..
- **変更概要 (JA):** include/openssl/opensslv.h: OPENSSL_VERSION_TEXT を "OpenSSL 1.1.1w [ipalongpatch_20261102]  11 Sep 2023" に変更。

## 1-2. 【警告: 曖昧な仕様】 Ambiguous specification notes / 仕様の曖昧さに関する注記

- (EN) The CVEINFO of the TAGGING patch is prescribed as 'Append-Tag-String-<tag string>' while CVEINFO is otherwise restricted to [A-Za-z0-9-] and 32 characters; the literal rule was followed with the brackets dropped: 'Append-Tag-String-ipalongpatch_20261102'.
  (JA) TAGGING パッチの CVEINFO は「Append-Tag-String-<タグ文字列>」と規定されているが、CVEINFO は本来 [A-Za-z0-9-] かつ 32 文字以内と制限されている。角括弧を除いた 'Append-Tag-String-ipalongpatch_20261102' として字義どおりの規則を優先した。
- (EN) Two of the Ubuntu security updates have no CVE (the Marvin attack implicit rejection, LP #2054090, and the 'HollowByte' DoS, LP #2161371); they are included as items 003 and 026 with the identifiers 'Marvin-LP2054090' and 'HollowByte' (<= 16 characters) because the task asks for every vulnerability fix applied by the vendor after 1.1.1w.
  (JA) Ubuntu のセキュリティ更新のうち 2 件には CVE が無い (Marvin 攻撃の implicit rejection、LP #2054090 と 'HollowByte' DoS、LP #2161371)。ベンダが 1.1.1w 以降に適用した全ての脆弱性修正を求める仕様に従い、識別子 'Marvin-LP2054090' と 'HollowByte' (16 文字以内) で項目 003 と 026 として含めた。
- (EN) The Ubuntu patch CVE-2026-2279x.patch covers CVE-2026-22795 and CVE-2026-22796 in one file; it was split into two per-CVE patches by file (PKCS#12 + s_client hardening -> 015, PKCS#7 -> 016) according to the official advisories.
  (JA) Ubuntu の CVE-2026-2279x.patch は CVE-2026-22795 と CVE-2026-22796 を 1 ファイルで扱っているため、公式アドバイザリに基づきファイル単位で 2 つの CVE 別パッチに分割した (PKCS#12 + s_client 堅牢化 -> 015、PKCS#7 -> 016)。
- (EN) CVE-2026-34182 (CMS AuthEnvelopedData) is listed in Ubuntu's series (CVE-2026-34182-pre1.patch) but OpenSSL 1.1.1 is not affected (no AuthEnvelopedData support) and the prerequisite change is already present in 1.1.1w; it is therefore not part of the patch set (see readme.md).
  (JA) CVE-2026-34182 (CMS AuthEnvelopedData) は Ubuntu の series に含まれる (CVE-2026-34182-pre1.patch) が、OpenSSL 1.1.1 は非影響 (AuthEnvelopedData 非対応) で、前提変更は 1.1.1w に既に含まれているため、パッチセットには含めていない (readme.md 参照)。
- (EN) The rule for the version text gives '(original) [tag] (date)'; the original 1.1.1 text has two spaces between version and date, which were kept: 'OpenSSL 1.1.1w [ipalongpatch_20261102]  11 Sep 2023'.
  (JA) バージョン文字列の規則は '(元の文字列) [タグ] (日付)' だが、元の 1.1.1 の文字列はバージョンと日付の間が 2 個の空白であり、これを維持した: 'OpenSSL 1.1.1w [ipalongpatch_20261102]  11 Sep 2023'。
- (EN) (34)(a-1) says MMM is the number of patches applied to (VAR_DIFF_SOFTWARE_ORIGINAL_VERSION); it was interpreted as the number of per-vulnerability patches applied to the target 1.1.1w (33 including TAGGING), consistent with (a-2).
  (JA) (34)(a-1) では MMM を (VAR_DIFF_SOFTWARE_ORIGINAL_VERSION) に当てるパッチ数としているが、(a-2) との整合から対象 1.1.1w に当てる脆弱性別パッチ数 (TAGGING を含め 33) と解釈した。

## 2. Definitions from section 0 of the task / タスク「0. バージョン・タスク名および URL の定義」の情報

| Variable / 変数 | Value / 値 |
|---|---|
| (VAR_TARGET_SOFTWARE_NAME) | OpenSSL |
| (VAR_TARGET_SOFTWARE_VERSION) | openssl-1.1.1w |
| (VAR_TARGET_SOFTWARE_SOURCE_CODE_FILENAME) | openssl-1.1.1w.tar.gz (SHA256 cf3098950cb4d853ad95c0841f1f9c6d3dc102dccfcacd521d93925208b76ac8) |
| (VAR_DIFF_SOFTWARE_ORIGINAL_VERSION) | openssl_1.1.1f |
| (VAR_DIFF_SOFTWARE_ORIGINAL_SOURCE_CODE_FILENAME) | openssl_1.1.1f.orig.tar.gz (SHA256 186c6bfe6ecfba7a5b48c47f8a1673d0f3b0e5ba2e25602dd23b629975da3f35) |
| (VAR_DIFF_SOFTWARE_PATCHED_VENDOR) | Canonical Ltd. (Ubuntu Security Team; Ubuntu 20.04 LTS 'focal' openssl package, built on the Debian OpenSSL Team packaging) - identified from debian/changelog, debian/control and the .dsc/.deb metadata |
| (VAR_DIFF_SOFTWARE_PATCHED_VERSION) | openssl_1.1.1f-1ubuntu2.24+esm6 |
| (VAR_DIFF_SOFTWARE_PATCHED_SOURCE_CODE_FILENAME) | openssl_1.1.1f-1ubuntu2.24+esm6.debian.tar.xz (SHA256 d57aba66e63067e3297086202045c056989b1d1e672bc5ca66ecfca3964d1dc0) |
| (VAR_DIFF_SOFTWARE_PATCHED_DIST_PACKAGES) | libssl1.1_1.1.1f-1ubuntu2.24+esm6_amd64.deb, libssl-dev_1.1.1f-1ubuntu2.24+esm6_amd64.deb, openssl_1.1.1f-1ubuntu2.24+esm6.dsc, openssl_1.1.1f-1ubuntu2.24+esm6_amd64.deb (SHA256 values in ipalongpatch_info/src_archives_digest_sha256.txt) |
| (VAR_MY_PATCHED_SOFTWARE_VERSION) | openssl-1.1.1w-ipalongpatch_20261102 |
| (VAR_MY_PATCHED_SOFTWARE_SOURCE_CODE_FILENAME) | openssl-1.1.1w-ipalongpatch_20261102-river_lantern.tar.gz |
| (VAR_NEW_ENGCODE) | river_lantern |
| (VAR_OLD_VER_FILES_URL) | https://drive.google.com/drive/u/0/folders/15I0YwnxAfW7ZZHhJiaMCmnBMc7BQtNpC |
| (VAR_NEW_VER_MATERIALS_URL) | (none / なし) |
| Patch tag string / パッチタグ文字列 | [ipalongpatch_20261102] |

## 3. AI model information / AI モデル情報

- (EN) Claude Mythos 5.1 (model id claude-mythos-5-1), reasoning effort: max (highest), running as Claude Code in the Anthropic claude.ai cloud sandbox (Ubuntu 24.04.5 LTS x86_64, 4 vCPU, 15 GiB RAM, container). Session start: 2026/11/02 10:48:22 (JST). This document generated: 2026/11/02 16:49:32 (JST).
- (JA) Claude Mythos 5.1 (モデル ID claude-mythos-5-1)、思考レベル (reasoning effort): max (最大)、Anthropic claude.ai クラウドサンドボックス上の Claude Code として動作 (Ubuntu 24.04.5 LTS x86_64、4 vCPU、15 GiB RAM、コンテナ)。セッション開始日時: 2026/11/02 10:48:22 (JST)。本文書の応答生成日時: 2026/11/02 16:49:32 (JST)。

## 4. The vulnerability / 脆弱性の内容

- **Identifier / 識別子:** TAGGING; not a vulnerability; IPALongPatch rule [PER_OSS_TAGGING_RULES:VER261102]
- **Title (EN):** Append the IPALongPatch tag string to OPENSSL_VERSION_TEXT (version tagging, not a vulnerability)
- **標題 (JA):** OPENSSL_VERSION_TEXT への IPALongPatch タグ文字列の追記 (バージョンタグ付け、脆弱性ではない)
- **Severity / 深刻度 (EN):** Not applicable (not a vulnerability).
- **深刻度 (JA):** 該当なし (脆弱性ではない)。
- **Publication / 公開日:** Not applicable
- **Summary (EN):** So that a patched build can be recognised externally, the human readable version text is changed from 'OpenSSL 1.1.1w  11 Sep 2023' to 'OpenSSL 1.1.1w [ipalongpatch_20261102]  11 Sep 2023'. OPENSSL_VERSION_NUMBER (0x1010117fL), the major/minor/patch numbers and SHLIB_VERSION_NUMBER are intentionally unchanged so that version checks keep working.
- **概要 (JA):** パッチ済みビルドを外形的に識別できるように、人間向けのバージョン文字列を 'OpenSSL 1.1.1w  11 Sep 2023' から 'OpenSSL 1.1.1w [ipalongpatch_20261102]  11 Sep 2023' に変更する。OPENSSL_VERSION_NUMBER (0x1010117fL)、major/minor/patch の各番号、SHLIB_VERSION_NUMBER は意図的に不変とし、バージョン検査が壊れないようにする。
- **Technical detail (EN):** include/openssl/opensslv.h defines OPENSSL_VERSION_TEXT, which is returned by OpenSSL_version(OPENSSL_VERSION) and printed by 'openssl version'. The tag is inserted between the version token and the date so that the second whitespace separated field ('1.1.1w') and the date remain intact for scripts that parse the output.
- **技術的詳細 (JA):** include/openssl/opensslv.h が OPENSSL_VERSION_TEXT を定義し、OpenSSL_version(OPENSSL_VERSION) が返し 'openssl version' が表示する。タグはバージョントークンと日付の間に挿入し、出力を解析するスクリプトのために空白区切り第 2 フィールド ('1.1.1w') と日付をそのまま残す。
- **Affected versions (EN):** Not applicable.
- **影響バージョン (JA):** 該当なし。

## 4-2. References / 参考 URL

(none / なし)

- (EN) Input reference files (local): openssl_1.1.1f-1ubuntu2.24+esm6.debian.tar.xz (debian/patches, debian/changelog), openssl_1.1.1f.orig.tar.gz, openssl-1.1.1w.tar.gz, libssl1.1 / libssl-dev / openssl .deb packages (used to confirm the vendor, version and build options).
- (JA) 入力参考ファイル (ローカル): openssl_1.1.1f-1ubuntu2.24+esm6.debian.tar.xz (debian/patches、debian/changelog)、openssl_1.1.1f.orig.tar.gz、openssl-1.1.1w.tar.gz、libssl1.1 / libssl-dev / openssl の .deb パッケージ (ベンダ・バージョン・ビルドオプションの確認に使用)。

## 4-3. Acknowledgements and copyright / 謝辞および著作権表記

- (EN) IPALongPatch rule [PER_OSS_TAGGING_RULES:VER261102] (task specification). OpenSSL copyright and licence as for item 001.
- (JA) IPALongPatch ルール [PER_OSS_TAGGING_RULES:VER261102] (タスク仕様)。OpenSSL の著作権・ライセンス表示は項目 001 と同じ。
- (EN) This port, its comments and this documentation were produced by the IPALongPatch process with generative AI (see section 3); the resulting source files remain subject to the OpenSSL licence of the 1.1.1 series (LICENSE file in the tree).
- (JA) 本移植、そのコメント、本ドキュメントは生成 AI による IPALongPatch 工程で作成した (3 節参照)。結果のソースファイルは引き続き 1.1.1 系の OpenSSL ライセンス (ツリー内 LICENSE ファイル) に従う。

## 5. Source code reading summary / 入力ソースコード読解結果

- (EN) include/openssl/opensslv.h (1.1.1w): '# define OPENSSL_VERSION_NUMBER  0x1010117fL' and '# define OPENSSL_VERSION_TEXT    "OpenSSL 1.1.1w  11 Sep 2023"'. crypto/cversion.c returns OPENSSL_VERSION_TEXT for OPENSSL_VERSION.
- (JA) 1.1.1w の include/openssl/opensslv.h: '# define OPENSSL_VERSION_NUMBER  0x1010117fL' と '# define OPENSSL_VERSION_TEXT    "OpenSSL 1.1.1w  11 Sep 2023"'。crypto/cversion.c は OPENSSL_VERSION に対して OPENSSL_VERSION_TEXT を返す。

## 6. Work performed (patching and testing) / 実施したパッチ当て・テスト作業

- (EN) Method common to all items: the Ubuntu patch was read in full and compared with the 1.1.1w sources (semantic review, not mechanical application); the change was re-applied with an exact-match replacement script (/home/user/work/port/033_*.py in the verification environment) or, for very large patches, applied with patch(1) and then adapted; every modified region was wrapped in '/* IPALongPatch: openssl-1.1.1w-ipalongpatch_20261102 --- PATCH_BEGIN --- ... */' and '--- PATCH_END ---' comment blocks (using the comment style of the file: C block comments, '#' for Perl/test data); the tree was rebuilt incrementally after each patch (0 compiler warnings in the final state of each patch; see section 2 of the 000 log), the relevant test recipes were run, and after the last patch the complete test suite was run on Linux (159 recipe files, 2658 tests, PASS) and a Windows x86_64 cross build (mingw64) was built and partly tested under wine (13 recipe files, 194 tests, PASS); the whole chain was repeated after the post-review amendments (readme.md section 14).
- (JA) 全項目共通の方法: Ubuntu パッチを全文精読し 1.1.1w のソースと突合 (機械的適用ではなく意味的なレビュー); 変更は厳密一致置換スクリプト (検証環境の /home/user/work/port/033_*.py) で再適用、または非常に大きなパッチは patch(1) で適用後に調整; 変更箇所はすべて '/* IPALongPatch: openssl-1.1.1w-ipalongpatch_20261102 --- PATCH_BEGIN --- ... */' と '--- PATCH_END ---' のコメントブロックで囲んだ (ファイルの慣習に従い C のブロックコメント、Perl/テストデータは '#'); 各パッチ後にツリーを増分ビルド (各パッチの最終状態でコンパイラ警告 0; 000 ログの 2 節参照) し関連テストレシピを実行、最終パッチ後に Linux で全テストスイート (159 レシピファイル、2658 テスト、PASS) を実行し、Windows x86_64 クロスビルド (mingw64) をビルドして wine 上で一部テスト (13 レシピファイル、194 テスト、PASS) を実施した。レビュー後の修正 (readme.md 14 節) の後に同じ一連の確認を繰り返した。
- (EN) Item specific: Applied as the last patch (script 033_TAGGING.py) with markers; the full test suite passes on the tagged tree; vercheck.c confirms identical OPENSSL_VERSION_NUMBER / OpenSSL_version_num() and the new text on Linux and on the Windows build under wine.
- (JA) 項目固有: 最後のパッチとして適用 (スクリプト 033_TAGGING.py) しマーカ付加。タグ付与後ツリーで全テスト合格。vercheck.c により Linux と wine 上の Windows 版で OPENSSL_VERSION_NUMBER / OpenSSL_version_num() が不変で新しい文字列が返ることを確認。

## 7. Concrete changes to the target source / 具体的な変更点

- (EN) include/openssl/opensslv.h: OPENSSL_VERSION_TEXT -> "OpenSSL 1.1.1w [ipalongpatch_20261102]  11 Sep 2023".
- (JA) include/openssl/opensslv.h: OPENSSL_VERSION_TEXT を "OpenSSL 1.1.1w [ipalongpatch_20261102]  11 Sep 2023" に変更。

Files, line ranges (in the delivered tree, including the IPALongPatch comment blocks) and enclosing functions / 変更ファイル・行範囲 (納品ツリー、IPALongPatch コメントブロックを含む)・包含関数:

| File / ファイル | Lines (delivered tree) / 行範囲 (納品ツリー) | Function(s) / 関数 |
|---|---|---|
| include/openssl/opensslv.h | 43-60 | extern "C" { |

Patch file / パッチファイル: `ipalongpatch_info/patch_files_for_each_cve/openssl-1.1.1w_ipalongpatch_033of033_TAGGING_Append-Tag-String-ipalongpatch_20261102.patch` (apply with `patch -p1` from the top of the openssl-1.1.1w tree after patches 001..032 / openssl-1.1.1w ツリーの最上位で、001..032 のパッチの後に `patch -p1` で適用).

## 8. Constraints, concerns and remaining issues / 制約事項・懸念事項・残課題

- (EN) Any tool that compares the full version text literally would see the new string; numeric checks are unaffected.
- (JA) バージョン文字列全体を文字どおり比較するツールは新しい文字列を見ることになるが、数値による検査は影響を受けない。
- (EN) General: the verification environment is a 4 vCPU Linux x86_64 VM; builds for other CPUs/OSes (ARM, PowerPC, s390x, macOS, VMS...) could not be executed, but all changes are plain C89-compatible code taken from the upstream/vendor patches, and the Windows build was verified with mingw64 + wine. Timing side-channel items are verified structurally plus with best-effort statistics.
- (JA) 一般: 検証環境は 4 vCPU の Linux x86_64 VM であり、他の CPU/OS (ARM、PowerPC、s390x、macOS、VMS 等) でのビルドは実行できなかったが、全変更は上流/ベンダパッチ由来の素の C89 互換コードであり、Windows ビルドは mingw64 + wine で検証した。タイミングサイドチャネル項目は構造的検証と可能な範囲の統計で検証した。
- (EN) Verification limitations (from the PoC verification of this item, see section 9): none
- (JA) 検証上の制約 (本項目の PoC 検証より、9 節参照): なし

## 9. Verification results / 検証結果

- **Verdict / 判定:** **PASS** (合格)
- **Start / 開始:** 2026/11/02 12:09:49 (JST)  **End / 終了:** 2026/11/02 12:09:51 (JST)  **Duration / 所要時間:** 00:00:02
- **Log file / ログファイル:** `ipalongpatch_info/logs/20261102_120949_033of033_TAGGING_Append-Tag-String-ipalongpatch_20261102.log`  (contains the environment information, every command, raw outputs and the final verdict / 環境情報、全コマンド、生の出力、最終判定を収録)
- **Method (EN):** vercheck.c against base and patched builds; openssl version on Linux (base/patched) and Windows x64 under wine
- **方法 (JA):** vercheck.c を未パッチ/パッチ済みビルドで実行; Linux (未パッチ/パッチ済み) と wine 上の Windows x64 版で openssl version を実行
- **Before the patch (EN):** OPENSSL_VERSION_TEXT = "OpenSSL 1.1.1w  11 Sep 2023"
- **パッチ前 (JA):** OPENSSL_VERSION_TEXT は "OpenSSL 1.1.1w  11 Sep 2023"
- **After the patch (EN):** OPENSSL_VERSION_TEXT = "OpenSSL 1.1.1w [ipalongpatch_20261102]  11 Sep 2023"; OPENSSL_VERSION_NUMBER unchanged (0x1010117fL)
- **パッチ後 (JA):** OPENSSL_VERSION_TEXT が "OpenSSL 1.1.1w [ipalongpatch_20261102]  11 Sep 2023" になり、OPENSSL_VERSION_NUMBER は不変 (0x1010117fL)
- **Regression / side-effect check (EN):** make test on the tagged tree: 2658 tests PASS
- **回帰・副作用確認 (JA):** タグ付与後ツリーで make test 2658 テスト合格
- **Limitations (EN):** none
- **制約 (JA):** なし
- **Tools / 使用ツール:** gcc, openssl version (Linux base/patched builds), wine 9.0 (mingw64 build of the patched tree), make test (full suite on the tagged tree)
- **PoC files / PoC ファイル (copied into ipalongpatch_info/docs/poc/ unless marked / 印の無いものは収録済み):** `ipalongpatch_info/docs/poc/033_TAGGING/vercheck.c`
- (EN) Whole-tree checks that cover this item too: the complete OpenSSL test suite on the final tree (Linux, 2658 tests, PASS), the mingw64 Windows build with 194 tests under wine (PASS), the ASan builds used by the PoC, and the (i)/(ii)/(iii) patch consistency check, all repeated after the post-review amendments - see ipalongpatch_info/logs/*_000of033_ALL_Build-and-test-suite-Linux-and-Windows.log and readme.md (sections 8, 9 and 14).
- (JA) 本項目にも関わるツリー全体の確認: 最終ツリーでの OpenSSL 全テストスイート (Linux、2658 テスト、PASS)、mingw64 Windows ビルドの wine 上 194 テスト (PASS)、PoC に用いた ASan ビルド、(i)/(ii)/(iii) パッチ一致検証。いずれもレビュー後の修正の後に再実施 - ipalongpatch_info/logs/*_000of033_ALL_Build-and-test-suite-Linux-and-Windows.log と readme.md (8、9、14 節) 参照。

### 9-1. Detailed verification report (PoC design, evidence excerpts, manual reproduction) / 詳細検証レポート (PoC 設計・証拠抜粋・手動再現手順)

The following report was written during the verification; paths refer to the verification environment (/home/user/work/...) and the PoC sources are included under ipalongpatch_info/docs/poc/. / 以下は検証時に作成したレポートである。パスは検証環境 (/home/user/work/...) のものであり、PoC のソースは ipalongpatch_info/docs/poc/ に収録している。

## 033 / TAGGING / Append-Tag-String-ipalongpatch_20261102

Log file / ログファイル: `20261102_120949_033of033_TAGGING_Append-Tag-String-ipalongpatch_20261102.log` (in /home/user/work/deliver/ipalongpatch_info/logs/)

Verdict / 判定: **PASS**

### Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コード上の観察)

Not a vulnerability. Patch 033 is the version-tag patch required by the task: it appends the tag string `[ipalongpatch_20261102]` to `OPENSSL_VERSION_TEXT` in include/openssl/opensslv.h so that `openssl version` and `OpenSSL_version(OPENSSL_VERSION)` identify the patched build. `OPENSSL_VERSION_NUMBER` (0x1010117fL) and the shared-library version are deliberately left unchanged, so ABI/version checks of applications keep working.

脆弱性ではない。パッチ 033 はタスクが要求するバージョンタグのパッチであり、include/openssl/opensslv.h の `OPENSSL_VERSION_TEXT` にタグ文字列 `[ipalongpatch_20261102]` を付加して、`openssl version` と `OpenSSL_version(OPENSSL_VERSION)` がパッチ版ビルドを識別できるようにする。`OPENSSL_VERSION_NUMBER` (0x1010117fL) と共有ライブラリのバージョンは意図的に不変とし、アプリケーションの ABI/バージョン検査が引き続き機能するようにしている。

### PoC design / PoC の設計

`vercheck.c` prints the compile-time `OPENSSL_VERSION_NUMBER` / `OPENSSL_VERSION_TEXT` and the run-time `OpenSSL_version_num()` / `OpenSSL_version(OPENSSL_VERSION)`; it is built against the unpatched and the patched build. `openssl version` is run on both Linux builds and on the mingw64 (Windows x86_64) build of the patched tree under wine.

`vercheck.c` はコンパイル時の `OPENSSL_VERSION_NUMBER` / `OPENSSL_VERSION_TEXT` と実行時の `OpenSSL_version_num()` / `OpenSSL_version(OPENSSL_VERSION)` を表示し、未パッチ版・パッチ版の両ビルドに対してビルドする。`openssl version` を Linux の両ビルドと、パッチ版ツリーの mingw64 (Windows x86_64) ビルドで wine 上で実行する。

### Observed behaviour BEFORE the patch (evidence excerpts) / 修正前の挙動 (証拠の抜粋)

```
OPENSSL_VERSION_NUMBER = 0x1010117fL
OPENSSL_VERSION_TEXT   = "OpenSSL 1.1.1w  11 Sep 2023"
OpenSSL_version(OPENSSL_VERSION) = "OpenSSL 1.1.1w  11 Sep 2023"
```

### Observed behaviour AFTER the patch / 修正後の挙動

```
OPENSSL_VERSION_NUMBER = 0x1010117fL          (unchanged / 不変)
OPENSSL_VERSION_TEXT   = "OpenSSL 1.1.1w [ipalongpatch_20261102]  11 Sep 2023"
OpenSSL_version(OPENSSL_VERSION) = "OpenSSL 1.1.1w [ipalongpatch_20261102]  11 Sep 2023"
patched (mingw64 under wine): OpenSSL 1.1.1w [ipalongpatch_20261102]  11 Sep 2023
```

### Regression check / 回帰確認

The full `make test` of the tagged tree passed (159 recipe files, 2658 tests, PASS); the Windows build passed 194 tests under wine. Only the text macro changed.

タグ付与後ツリーの完全な `make test` は合格 (レシピ 159 ファイル、2658 テスト、PASS)。Windows ビルドは wine 上で 194 テスト合格。変更はテキストマクロのみ。

### How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```bash
cd /home/user/work/poc/033_TAGGING
gcc -I/home/user/work/patched/build/include -I/home/user/work/patched/openssl-1.1.1w-ipalongpatch_20261102/include vercheck.c -L/home/user/work/patched/build -lcrypto -Wl,-rpath,/home/user/work/patched/build -o vercheck_patched && ./vercheck_patched
/home/user/work/patched/build/util/shlib_wrap.sh /home/user/work/patched/build/apps/openssl version
cd /home/user/work/patched/build-mingw64/apps && wine ./openssl.exe version
```

### Limitations / notes / 制約・注記

None. / 特になし。

