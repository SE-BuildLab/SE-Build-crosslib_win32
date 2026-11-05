# IPALongPatch readme - openssl-1.1.1w-ipalongpatch_20261102

`DNNT 261102_EEHXW5 IPALongPatch openssl-1.1.1w-ipalongpatch_20261102 OpenSSL_1.1.1f_From_Ubuntu`

- Generated / 生成日時: 2026/11/02 16:49:32 (JST). Session start / セッション開始: 2026/11/02 10:48:22 (JST).
- AI (EN): Claude Mythos 5.1 (model id claude-mythos-5-1), reasoning effort: max (highest), running as Claude Code in the Anthropic claude.ai cloud sandbox (Ubuntu 24.04.5 LTS x86_64, 4 vCPU, 15 GiB RAM, container). / AI (JA): Claude Mythos 5.1 (モデル ID claude-mythos-5-1)、思考レベル (reasoning effort): max (最大)、Anthropic claude.ai クラウドサンドボックス上の Claude Code として動作 (Ubuntu 24.04.5 LTS x86_64、4 vCPU、15 GiB RAM、コンテナ)。

## 1. What this is / 本成果物について

(EN) `openssl-1.1.1w-ipalongpatch_20261102-river_lantern.tar.gz` is OpenSSL 1.1.1w (the last public release of the 1.1.1 series, 2023-09-11, which no longer receives public security fixes) with 32 security fixes back-ported from Canonical's Ubuntu 20.04 package openssl 1.1.1f-1ubuntu2.24+esm6 (which itself back-ports the OpenSSL 1.1.1 premium / 3.x fixes), plus a version-text tag. The tree builds and tests exactly like the original tarball; every source modification is enclosed in `IPALongPatch ... PATCH_BEGIN/PATCH_END` comment blocks that state the origin and rationale. This directory (`ipalongpatch_info/`) holds the patches, verification logs and documentation and is the only addition to the upstream directory layout.

(JA) `openssl-1.1.1w-ipalongpatch_20261102-river_lantern.tar.gz` は、公開セキュリティ修正が提供されなくなった OpenSSL 1.1.1 系最後の公開版 1.1.1w (2023-09-11) に、Canonical の Ubuntu 20.04 パッケージ openssl 1.1.1f-1ubuntu2.24+esm6 (それ自体が OpenSSL 1.1.1 premium / 3.x の修正をバックポートしたもの) から 32 件のセキュリティ修正を移植し、バージョン文字列タグを付けたものである。ツリーは元の tarball と全く同じようにビルド・テストでき、全てのソース変更は出典と根拠を記した `IPALongPatch ... PATCH_BEGIN/PATCH_END` コメントブロックで囲まれている。本ディレクトリ (`ipalongpatch_info/`) にパッチ、検証ログ、ドキュメントを収め、上流のディレクトリ構成への追加はこれのみである。

## 2. Definitions (task section 0) / 定義

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

## 3. Directory layout / ディレクトリ構成

```
ipalongpatch_info/
  readme.md                          this file / 本ファイル
  PATCH_LIST.txt                     catalogue of the 33 patches with verification summary / 33 パッチの目録と検証サマリ
  CVE_LIST.txt                       list of the 32 fixed vulnerabilities / 解決済み脆弱性 32 件の一覧
  src_archives_digest_sha256.txt     SHA-256 of the 7 input files / 入力 7 ファイルの SHA-256
  src_files_digest_sha256.txt        SHA-256 of every file inside the input archives ([archive]./path) / 入力アーカイブ内の全ファイルの SHA-256
  patch_files_for_each_cve/          one patch per vulnerability, apply in order 001..033 / 脆弱性別パッチ (001..033 の順に適用)
  patch_file_consolidated/           the same 33 patches as one file / 33 パッチを 1 本にした集約パッチ
  logs/                              verification logs (environment, commands, gdb/ASan/valgrind evidence) / 検証ログ (環境情報、コマンド、gdb/ASan/valgrind の証拠)
  docs/                              per-vulnerability reports (.md + .html), index .html, this prompt (UserInputPrompt), PoC sources (docs/poc/) / 脆弱性別レポート (.md + .html)、索引 .html、入力プロンプト (UserInputPrompt)、PoC ソース (docs/poc/)
```

## 4. The patches / パッチ一覧

| # | Identifier / 識別子 | Title / 標題 | Severity (OpenSSL) / 深刻度 (OpenSSL) | Verdict / 判定 | Log / ログ |
|---|---|---|---|---|---|
| 001 | CVE-2023-5678 | Excessive time spent in DH check / generation with large Q parameter value / 過大な Q パラメータ値による DH 検査/鍵生成での過大な処理時間 (DoS) | Low | PASS | 20261102_120524_001of033_CVE-2023-5678_DH-large-Q-excessive-time-DoS.log |
| 002 | CVE-2024-0727 | PKCS12 decoding crashes (NULL pointer dereference) on maliciously formatted PKCS12 files / 悪意ある形式の PKCS12 ファイルによる PKCS12 デコードのクラッシュ (NULL ポインタ参照) | Low | PASS | 20261102_120658_002of033_CVE-2024-0727_PKCS12-NULL-ContentInfo-crash.log |
| 003 | Marvin-LP2054090 | Marvin Attack mitigation: implicit rejection for RSA PKCS#1 v1.5 decryption / Marvin 攻撃対策: RSA PKCS#1 v1.5 復号における implicit rejection (暗黙の拒否) | no CVE | PASS | 20261102_120117_003of033_Marvin-LP2054090_Marvin-RSA-PKCS1-implicit-reject.log |
| 004 | CVE-2024-2511 | Unbounded memory growth with session handling in TLSv1.3 / TLSv1.3 のセッション処理におけるメモリの無制限な増大 | Low | PASS | 20261102_121141_004of033_CVE-2024-2511_TLS13-session-cache-unbounded.log |
| 005 | CVE-2024-4741 | Use After Free with SSL_free_buffers() / SSL_free_buffers() に起因する use-after-free | Low | PASS | 20261102_122048_005of033_CVE-2024-4741_SSL-free-buffers-use-after-free.log |
| 006 | CVE-2024-5535 | SSL_select_next_proto() buffer overread / SSL_select_next_proto() のバッファ越え読み出し | Low | PASS | 20261102_122754_006of033_CVE-2024-5535_SSL-select-next-proto-overread.log |
| 007 | CVE-2024-9143 | Low-level invalid GF(2^m) parameters lead to OOB memory access / 低レベル API に渡される不正な GF(2^m) パラメータによる境界外メモリアクセス | Low | PASS | 20261102_121100_007of033_CVE-2024-9143_GF2m-poly2arr-OOB-memory-access.log |
| 008 | CVE-2024-13176 | Timing side-channel in ECDSA signature computation (Minerva type attack) / ECDSA 署名計算のタイミングサイドチャネル (Minerva 型攻撃) | Low | PASS | 20261102_121206_008of033_CVE-2024-13176_Minerva-ECDSA-timing-side-chan.log |
| 009 | CVE-2025-9230 | Out-of-bounds read & write in RFC 3211 KEK Unwrap (CMS password based recipients) / RFC 3211 KEK アンラップ (CMS パスワードベース受信者) の境界外読み出し・書き込み | Moderate | PASS | 20261102_120333_009of033_CVE-2025-9230_CMS-PWRI-KEK-unwrap-OOB-rw.log |
| 010 | CVE-2025-68160 | Heap out-of-bounds write in BIO_f_linebuffer on short writes / short write 時の BIO_f_linebuffer におけるヒープ境界外書き込み | Low | PASS | 20261102_121611_010of033_CVE-2025-68160_BIO-f-linebuffer-heap-overflow.log |
| 011 | CVE-2025-69418 | Unauthenticated / unencrypted trailing bytes with low-level OCB function calls (AES-NI / HW stream path) / 低レベル OCB 関数 (AES-NI / HW ストリーム経路) における末尾バイトの未暗号化・未認証 | Low | PASS | 20261102_122439_011of033_CVE-2025-69418_OCB-AESNI-tail-bytes-unencrypted.log |
| 012 | CVE-2025-69419 | Out of bounds write in PKCS12_get_friendlyname() UTF-8 conversion / PKCS12_get_friendlyname() の UTF-8 変換における境界外書き込み | Low | PASS | 20261102_121342_012of033_CVE-2025-69419_PKCS12-friendlyName-UTF8-OOB.log |
| 013 | CVE-2025-69420 | Missing ASN1_TYPE validation in TS_RESP_verify_response() (ESS signingCertificate attribute) / TS_RESP_verify_response() における ASN1_TYPE 検証漏れ (ESS signingCertificate 属性) | Low | PASS | 20261102_121342_013of033_CVE-2025-69420_TS-RESP-verify-ASN1-TYPE-check.log |
| 014 | CVE-2025-69421 | NULL pointer dereference in PKCS12_item_decrypt_d2i() (PKCS12_item_decrypt_d2i_ex in 3.x) / PKCS12_item_decrypt_d2i() (3.x では PKCS12_item_decrypt_d2i_ex) の NULL ポインタ参照 | Low | PASS | 20261102_121856_014of033_CVE-2025-69421_PKCS12-item-decrypt-NULL-deref.log |
| 015 | CVE-2026-22795 | Missing ASN1_TYPE validation / type confusion in PKCS#12 parsing (friendlyName and localKeyID attributes) / PKCS#12 解析 (friendlyName / localKeyID 属性) における ASN1_TYPE 検証漏れ・型混同 | Low | PASS | 20261102_121856_015of033_CVE-2026-22795_PKCS12-attr-type-confusion-DoS.log |
| 016 | CVE-2026-22796 | ASN1_TYPE type confusion in PKCS7_digest_from_attributes() (PKCS#7 signature verification) / PKCS7_digest_from_attributes() (PKCS#7 署名検証) における ASN1_TYPE 型混同 | Low | PASS | 20261102_121857_016of033_CVE-2026-22796_PKCS7-digest-attr-type-confusion.log |
| 017 | CVE-2026-28387 | Potential use-after-free in DANE client code (dane_match_cert() freed the matched certificate with OPENSSL_free()) / DANE クライアントコードの use-after-free (dane_match_cert() が一致証明書を OPENSSL_free() で解放) | Low | PASS | 20261102_124214_017of033_CVE-2026-28387_DANE-match-cert-wrong-free-UAF.log |
| 018 | CVE-2026-28388 | NULL pointer dereference when processing a delta CRL without a CRL Number extension / CRL Number 拡張の無い差分 CRL 処理時の NULL ポインタ参照 | Low | PASS | 20261102_124759_018of033_CVE-2026-28388_DeltaCRL-no-CRLNumber-NULL-deref.log |
| 019 | CVE-2026-28389 | Possible NULL dereference when processing CMS KeyAgreeRecipientInfo without algorithm parameters / アルゴリズムパラメータの無い CMS KeyAgreeRecipientInfo 処理時の NULL 参照 | Low | PASS | 20261102_122406_019of033_CVE-2026-28389_CMS-KARI-no-params-NULL-deref.log |
| 020 | CVE-2026-28390 | Possible NULL dereference when processing CMS KeyTransRecipientInfo (RSA-OAEP pSourceFunc without parameters) / CMS KeyTransRecipientInfo (パラメータ無しの RSA-OAEP pSourceFunc) 処理時の NULL 参照 | Low | PASS | 20261102_123942_020of033_CVE-2026-28390_CMS-KTRI-OAEP-label-NULL-deref.log |
| 021 | CVE-2026-42766 | Possible NULL dereference in password-based CMS decryption (absent keyDerivationAlgorithm) / パスワードベース CMS 復号における NULL 参照 (keyDerivationAlgorithm 欠落) | Low | PASS | 20261102_121449_021of033_CVE-2026-42766_CMS-PWRI-no-KDF-alg-NULL-deref.log |
| 022 | CVE-2026-9076 | Out-of-bounds read in CMS password-based decryption (kek_unwrap_key() check bytes with a small block size KEK cipher) / CMS パスワードベース復号の境界外読み出し (小ブロック長 KEK 暗号での kek_unwrap_key() チェックバイト) | Low | PASS | 20261102_121750_022of033_CVE-2026-9076_CMS-PWRI-checkbyte-OOB-read.log |
| 023 | CVE-2026-7383 | Possible heap buffer overflow in ASN.1 multibyte string conversion (ASN1_mbstring_ncopy) / ASN.1 マルチバイト文字列変換 (ASN1_mbstring_ncopy) におけるヒープバッファオーバーフロー | Low | PASS | 20261102_123829_023of033_CVE-2026-7383_ASN1-mbstring-ncopy-int-overflow.log |
| 024 | CVE-2026-34180 | Heap buffer over-read in ASN.1 content parsing (length truncation in asn1_ex_c2i / ASN1_STRING_set) / ASN.1 内容解析のヒープ境界外読み出し (asn1_ex_c2i / ASN1_STRING_set の長さ切り捨て) | Low | PASS | 20261102_123847_024of033_CVE-2026-34180_ASN1-STRING-set-len-truncation.log |
| 025 | CVE-2026-45447 | Heap use-after-free in the PKCS7_verify() function (empty digestAlgorithms SET) / PKCS7_verify() のヒープ use-after-free (空の digestAlgorithms SET) | High | PASS | 20261102_123854_025of033_CVE-2026-45447_PKCS7-verify-use-after-free.log |
| 026 | HollowByte | 'HollowByte' denial of service: handshake message buffer allocated up front for a peer-claimed (huge) message size / 'HollowByte' DoS: ピアが申告した (巨大な) メッセージ長ぶんのハンドシェイクバッファを前払いで確保 | no CVE | PASS | 20261102_123308_026of033_HollowByte_LP2161371-TLS-init-buf-mem-DoS.log |
| 027 | CVE-2026-54874 | Excessive memory use buffering DTLS records for a future epoch / 将来エポックの DTLS レコードバッファリングによる過大なメモリ使用 | Low | PASS | 20261102_124251_027of033_CVE-2026-54874_DTLS-future-epoch-buffer-memDoS.log |
| 028 | CVE-2026-63072 | Heap buffer overflow (8-byte OOB write) in CMS key unwrapping with AES-WRAP-PAD / AES-WRAP-PAD による CMS 鍵アンラップのヒープバッファオーバーフロー (8 バイト OOB 書き込み) | Moderate | PASS | 20261102_123339_028of033_CVE-2026-63072_CMS-AESWRAPPAD-unwrap-OOB-write.log |
| 029 | CVE-2026-35189 | Excessive memory allocation in relative CRLDP processing / 相対 CRLDP (nameRelativeToCRLIssuer) 処理における過大なメモリ割り当て | Low | PASS | 20261102_124932_029of033_CVE-2026-35189_Relative-CRLDP-excessive-memory.log |
| 030 | CVE-2026-54872 | Timing side-channel in scalar multiplication for non-NIST EC curves (Montgomery ladder scalar padding) / 非 NIST 楕円曲線のスカラー倍算 (Montgomery ラダーのスカラー詰め) のタイミングサイドチャネル | Low | PASS | 20261102_122354_030of033_CVE-2026-54872_EC-ladder-scalar-timing-leak.log |
| 031 | CVE-2026-77696 | Timing side-channel in SM2 signature generation / SM2 署名生成のタイミングサイドチャネル | Low | PASS | 20261102_123554_031of033_CVE-2026-77696_SM2-sig-gen-timing-side-channel.log |
| 032 | CVE-2026-84782 | DTLS retransmits handshake messages from a stale buffer offset / DTLS が古いバッファオフセットからハンドシェイクメッセージを再送する | High | PASS | 20261102_130106_032of033_CVE-2026-84782_DTLS-retransmit-stale-init-off.log |
| 033 | TAGGING | Append the IPALongPatch tag string to OPENSSL_VERSION_TEXT (version tagging, not a vulnerability) / OPENSSL_VERSION_TEXT への IPALongPatch タグ文字列の追記 (バージョンタグ付け、脆弱性ではない) | n/a | PASS | 20261102_120949_033of033_TAGGING_Append-Tag-String-ipalongpatch_20261102.log |

(EN) Verification verdicts: 33 of 33 items PASS. All identifiers, severities, dates and references were researched on the public advisories (openssl-library.org), Ubuntu Security (ubuntu.com/security, USN), CVE.org/NVD and the vendor patch headers; see docs/ for details per item.
(JA) 検証判定: 33 / 33 項目が合格 (PASS)。識別子・深刻度・日付・参考情報は公開アドバイザリ (openssl-library.org)、Ubuntu Security (ubuntu.com/security、USN)、CVE.org/NVD、ベンダパッチのヘッダから調査した。項目ごとの詳細は docs/ 参照。

## 5. What was NOT ported and why / 移植しなかったものとその理由

(EN) The Ubuntu series lists 143 patches (140 .patch files directly under debian/patches/ plus 3 under debian/patches/lp1978093/). Everything up to and including the fixes for CVE-2023-2650, CVE-2023-3446 and CVE-2023-3817 (openssl 1.1.1f-1ubuntu2.20, 2023-10) is already part of OpenSSL 1.1.1u/1.1.1v/1.1.1w (duplicates excluded as required by task item (23)); Debian/Ubuntu packaging patches (s390x assembly pack, debian-targets, man-section, no-symbolic, pic, tests-use-seclevel-1, tls1.2-min-seclevel2, c_rehash-compat, Launchpad bug fixes lp-19xxxxx) are distribution specific and were not ported. CVE-2026-34182 (CMS AuthEnvelopedData forgery) does not affect OpenSSL 1.1.1 (no AuthEnvelopedData support; the OpenSSL advisory, CVE.org and Ubuntu all state 1.1.1 is not affected) and the only related Ubuntu change (CVE-2026-34182-pre1.patch, 'Ensure ossl_cms_EncryptedContent_init_bio() reports an error on no OID') is already present in 1.1.1w (crypto/cms/cms_enc.c, CMS_R_UNSUPPORTED_CONTENT_ENCRYPTION_ALGORITHM), so nothing was needed.

(JA) Ubuntu の series には 143 本のパッチが列挙されている (debian/patches/ 直下に 140 本、debian/patches/lp1978093/ に 3 本)。CVE-2023-2650、CVE-2023-3446、CVE-2023-3817 の修正 (openssl 1.1.1f-1ubuntu2.20、2023-10) までは OpenSSL 1.1.1u/1.1.1v/1.1.1w に既に含まれる (タスク (23) の要求どおり重複を除外)。Debian/Ubuntu のパッケージング用パッチ (s390x アセンブリ、debian-targets、man-section、no-symbolic、pic、tests-use-seclevel-1、tls1.2-min-seclevel2、c_rehash-compat、Launchpad バグ修正 lp-19xxxxx) はディストリビューション固有であり移植していない。CVE-2026-34182 (CMS AuthEnvelopedData 偽造) は OpenSSL 1.1.1 に影響しない (AuthEnvelopedData 非対応; OpenSSL アドバイザリ、CVE.org、Ubuntu のいずれも 1.1.1 非影響と記載) うえ、唯一関連する Ubuntu の変更 (CVE-2026-34182-pre1.patch、'Ensure ossl_cms_EncryptedContent_init_bio() reports an error on no OID') は 1.1.1w に既に含まれている (crypto/cms/cms_enc.c、CMS_R_UNSUPPORTED_CONTENT_ENCRYPTION_ALGORITHM) ため、対応は不要であった。

## 6. How the patches were made / パッチの作成方法

(EN) For each item the Ubuntu patch (debian/patches/*.patch, with its upstream commit reference) and the official advisory were studied, the corresponding 1.1.1w code was read, and the fix was re-applied semantically with exact-match replacement scripts (or patch(1) followed by adaptation for the largest ones), adding the IPALongPatch comment blocks. Where 1.1.1w differed from 1.1.1f the port was adapted by hand: CVE-2026-45447 (different memory-BIO optimisation line in PKCS7_verify()), CVE-2026-28388 and CVE-2026-84782 (test recipes/test files differ), the Marvin implicit rejection (manual pages reworded for 1.1.1, proper RSA error function codes), CVE-2026-54872 (BN_F_BN_SET_TOP_FIXED error code), CVE-2026-35189 (X509_NAME_dup() const-ness in 1.1.1), CVE-2026-28390 (empty OAEP label accepted). Portability was kept in mind throughout (C89, no compiler extensions except the existing GNU-C-guarded inline asm barrier with a volatile fallback, BIO_snprintf() instead of snprintf() in tests, Windows-safe sleep in the DTLS test). Each patch was built incrementally with 0 warnings, committed to a private git history from which the per-CVE patch files (git diff between consecutive commits, with explanatory headers) and the consolidated patch (git diff base..final) were generated.

(JA) 各項目について Ubuntu パッチ (debian/patches/*.patch とその上流コミット参照) と公式アドバイザリを精査し、対応する 1.1.1w のコードを読み、厳密一致置換スクリプト (最大級のものは patch(1) 適用後に調整) で修正を意味的に再適用し、IPALongPatch コメントブロックを付加した。1.1.1w が 1.1.1f と異なる箇所は手作業で適合させた: CVE-2026-45447 (PKCS7_verify() のメモリ BIO 最適化行の差異)、CVE-2026-28388 と CVE-2026-84782 (テストレシピ/テストファイルの差異)、Marvin implicit rejection (マニュアルページの 1.1.1 向け書き直し、正式な RSA エラー関数コード)、CVE-2026-54872 (BN_F_BN_SET_TOP_FIXED エラーコード)、CVE-2026-35189 (1.1.1 の X509_NAME_dup() の const 性)、CVE-2026-28390 (空の OAEP ラベルの受理)。移植性を常に考慮した (C89、既存の GNU C ガード付きインラインアセンブラバリア (volatile フォールバック付き) 以外のコンパイラ拡張を使わない、テストでは snprintf() の代わりに BIO_snprintf()、DTLS テストでは Windows でも安全な sleep)。各パッチは警告 0 で増分ビルドし、非公開の git 履歴にコミットし、そこから CVE 別パッチファイル (連続コミット間の git diff + 説明ヘッダ) と集約パッチ (git diff base..final) を生成した。

## 7. Why the vulnerabilities are resolved / 脆弱性が解消したといえる理由

(EN) Each port implements the same logical change as the upstream OpenSSL fix (validated against the Ubuntu backport line by line) and was verified dynamically: for every item a proof-of-concept was executed against the unpatched 1.1.1w build (debug and AddressSanitizer builds) showing the crash / out-of-bounds access / use-after-free / excessive memory or time / API oracle, and against the patched build showing a clean error or correct behaviour; benign use of the same feature was re-tested for regressions, and valgrind/ASan were used to check for memory errors and leaks. The details, raw outputs and gdb/ASan traces are in logs/ and docs/.

(JA) 各移植は上流 OpenSSL の修正と同じ論理的変更を実装している (Ubuntu バックポートと行単位で突合して確認) うえ、動的にも検証した: 全項目について PoC を未パッチ 1.1.1w ビルド (デバッグ版と AddressSanitizer 版) に対して実行してクラッシュ / 境界外アクセス / use-after-free / 過大なメモリ・時間 / API オラクルを示し、パッチ済みビルドではクリーンなエラーまたは正しい挙動になることを示した。同じ機能の正規利用の回帰確認も行い、valgrind/ASan でメモリエラーとリークを確認した。詳細、生の出力、gdb/ASan のトレースは logs/ と docs/ にある。

## 8. Tests performed / 実施したテスト

(EN) 1) Baseline: unpatched 1.1.1w built (`./config -d shared enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers`, gcc 13.3.0) and `make test` run: 159 recipe files, 2656 tests, PASS. 2) After each of the 33 patches: incremental rebuild (0 compiler warnings in the final state of each patch; the first version of patch 029 produced one -Wdiscarded-qualifiers warning, visible in the 029 and 030 builds until 029 was amended - see section 2 of the 000 log) and the relevant test recipes. 3) Final tree: full `make test` 159 recipe files, 2658 tests, PASS (the two additional tests are the new regression tests of patches 018 and 025; patches 007, 028 and 032 added C-level tests inside existing recipes). 4) Windows x86_64: `Configure mingw64 --cross-compile-prefix=x86_64-w64-mingw32-` (gcc 13-win32), build OK, `openssl.exe version` and functional checks (PKCS12, CMS RSA/EC/PWRI, CRL verification, S/MIME, RSA implicit rejection) under wine 9.0, and 13 test recipes (194 tests) run under wine with EXE_SHELL=wine: PASS. 5) AddressSanitizer builds of the unpatched and patched trees for the PoC runs. 6) Per-vulnerability PoCs with gdb, ASan and valgrind (see logs/ and docs/poc/): the 32 vulnerability items were verified by five delegated verification agents (groups: CMS recipient info; PKCS#12/PKCS#7/ASN.1; X.509/CRL/DANE, public-key/symmetric crypto and BIO; TLS/DTLS; timing side channels and RSA) under the common instructions docs/poc/COMMON.md, each item against an unpatched and a patched build (debug and ASan). The agent of the timing group was terminated by the platform after finishing the measurements of its last item; the orchestrating session completed items 008, 030 and 031 (regression checks, formal logs) from the unaltered raw captures, as recorded in those logs. 7) Patch consistency: the 33 individual patches applied in order and the consolidated patch applied to pristine 1.1.1w trees, compared with the delivered tree. 8) After the post-review amendments (section 14) the whole chain was repeated: rebuild (0 warnings), util/ck_errf.pl -strict, the complete test suite (159 recipe files, 2658 tests, PASS), ASan and mingw64 rebuilds, the wine subset (13 recipe files, 194 tests, PASS) and the (i)/(ii)/(iii) check (identical).

(JA) 1) ベースライン: 未パッチ 1.1.1w をビルド (`./config -d shared enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers`、gcc 13.3.0) し `make test`: 159 レシピファイル、2656 テスト、PASS。2) 33 パッチの各適用後: 増分ビルド (各パッチの最終状態でコンパイラ警告 0; パッチ 029 の初版が -Wdiscarded-qualifiers 警告 1 件を生じ、029 修正前の 029/030 ビルドに現れた - 000 ログの 2 節参照) と関連テストレシピ。3) 最終ツリー: `make test` 全体 159 レシピファイル、2658 テスト、PASS (増えた 2 テストはパッチ 018 と 025 の新規回帰テスト; パッチ 007、028、032 は既存レシピ内に C レベルのテストを追加)。4) Windows x86_64: `Configure mingw64 --cross-compile-prefix=x86_64-w64-mingw32-` (gcc 13-win32) でビルド成功、wine 9.0 上で `openssl.exe version` と機能確認 (PKCS12、CMS RSA/EC/PWRI、CRL 検証、S/MIME、RSA implicit rejection)、EXE_SHELL=wine で 13 テストレシピ (194 テスト) を実行: PASS。5) PoC 用に未パッチ/パッチ済みの AddressSanitizer ビルド。6) 脆弱性ごとの PoC (gdb、ASan、valgrind; logs/ と docs/poc/ 参照): 32 件の脆弱性項目は、共通指示 docs/poc/COMMON.md の下で 5 つの検証エージェント (グループ: CMS 受信者情報; PKCS#12/PKCS#7/ASN.1; X.509/CRL/DANE・公開鍵/対称暗号・BIO; TLS/DTLS; タイミングサイドチャネルと RSA) に委任し、各項目を未パッチ版とパッチ版のビルド (デバッグ版と ASan 版) に対して検証した。タイミンググループのエージェントは最後の項目の計測を終えた後にプラットフォームにより停止されたため、統括セッションが項目 008、030、031 (回帰確認、正式ログ) を改変なしの生出力から完了した (各ログに記録)。7) パッチ一致検証: 個別 33 パッチの順次適用と集約パッチの適用を素の 1.1.1w に対して行い納品ツリーと比較。8) レビュー後の修正 (14 節) の後、一連の確認を繰り返した: 再ビルド (警告 0)、util/ck_errf.pl -strict、全テストスイート (159 レシピファイル、2658 テスト、PASS)、ASan と mingw64 の再ビルド、wine でのサブセット (13 レシピファイル、194 テスト、PASS)、(i)/(ii)/(iii) 検証 (一致)。

## 9. Consistency check (i)/(ii)/(iii) - PASSED / 一致検証 (i)/(ii)/(iii) - 合格

(EN) **Result: PASS.** (i) openssl-1.1.1w.tar.gz extracted and the 33 patches of patch_files_for_each_cve/ applied in order with `patch -p1` (all applied cleanly, no fuzz, no offset, no rejects); (ii) openssl-1.1.1w.tar.gz extracted and patch_file_consolidated/openssl-1.1.1w_ipalongpatch_consolidated.patch applied with `patch -p1`; (iii) the delivered tree without ipalongpatch_info/. `diff -r` reports no difference between (i) and (ii) and between (i) and (iii). Summary: 3108 files plus the empty directory wycheproof/ in each result (pristine 1.1.1w: 3104 files; the 4 new files are test data added by patches 018 and 025); 85 files differ from pristine 1.1.1w (81 modified + 4 new): 67 C sources/headers under crypto/, ssl/, include/ and apps/ (patches 001-032), include/openssl/opensslv.h (patch 033), 6 manual pages under doc/, 11 files under test/ (7 modified + 4 new). The check was first performed at 12:09 (JST) on the tree before the post-review amendments and repeated at 16:34 (JST) after them, both in the verification environment; it is recorded in sections 10 and 11 of logs/*_000of033_ALL_Build-and-test-suite-Linux-and-Windows.log, and the extracted final tarball was compared again (section 15).

(JA) **結果: 合格。** (i) openssl-1.1.1w.tar.gz を展開し patch_files_for_each_cve/ の 33 パッチを順に `patch -p1` で適用 (全て fuzz・offset・reject なしで適用成功); (ii) openssl-1.1.1w.tar.gz を展開し patch_file_consolidated/openssl-1.1.1w_ipalongpatch_consolidated.patch を `patch -p1` で適用; (iii) ipalongpatch_info/ を除く納品ツリー。`diff -r` で (i) と (ii)、(i) と (iii) に差分なし。サマリ: 各結果 3108 ファイルと空ディレクトリ wycheproof/ (素の 1.1.1w は 3104 ファイル; 新規 4 ファイルはパッチ 018 と 025 のテストデータ); 素の 1.1.1w との差分は 85 ファイル (既存ファイルの変更 81 + 新規 4): パッチ 001〜032 による crypto/、ssl/、include/、apps/ 配下の C ソース/ヘッダ 67、パッチ 033 による include/openssl/opensslv.h、doc/ 配下のマニュアル 6、test/ 配下 11 (変更 7 + 新規 4)。検証はレビュー後の修正前のツリーに対して 12:09 (JST) に、修正後に 16:34 (JST) に、いずれも検証環境で実施し、logs/*_000of033_ALL_Build-and-test-suite-Linux-and-Windows.log の 10 節と 11 節に記録した。展開した最終 tar.gz も再度比較した (15 節)。

## 10. Behavioural changes to be aware of / 注意すべき挙動変更

- (EN) RSA PKCS#1 v1.5 decryption (RSA_private_decrypt()/EVP_PKEY_decrypt() with RSA_PKCS1_PADDING) uses implicit rejection (patch 003): a padding failure returns a deterministic pseudo random message instead of an error, as in OpenSSL 3.2+. Use RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING or the EVP_PKEY_CTRL_RSA_IMPLICIT_REJECTION ctrl (`-pkeyopt rsa_pkcs1_implicit_rejection:0`) for the old behaviour. TLS, PKCS7 and CMS are unaffected.
  (JA) RSA PKCS#1 v1.5 復号 (RSA_PKCS1_PADDING の RSA_private_decrypt()/EVP_PKEY_decrypt()) は implicit rejection (パッチ 003) を使い、パディング失敗時にエラーではなく決定的な疑似乱数メッセージを返す (OpenSSL 3.2 以降と同じ)。旧挙動には RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING または EVP_PKEY_CTRL_RSA_IMPLICIT_REJECTION ctrl (`-pkeyopt rsa_pkcs1_implicit_rejection:0`) を使う。TLS、PKCS7、CMS は非影響。
- (EN) PKCS7_verify() reads the caller's memory BIO directly (patch 025, as OpenSSL 3.x); SSL_free_buffers() returns 0 in more situations (patch 005); SSL_select_next_proto() returns NULL/0 for invalid client lists (patch 006); DTLSv1_handle_timeout() does not retransmit while a handshake write is suspended (patch 032); the full name of a certificate's relative CRL distribution points is no longer cached in the X509 object (patch 029); DTLS buffers at most 16 next-epoch records (patch 027); the version text carries the tag `[ipalongpatch_20261102]` (patch 033).
  (JA) PKCS7_verify() は呼び出し側のメモリ BIO を直接読む (パッチ 025、OpenSSL 3.x と同じ); SSL_free_buffers() が 0 を返す状況が増える (パッチ 005); SSL_select_next_proto() は不正なクライアントリストに NULL/0 を返す (パッチ 006); DTLSv1_handle_timeout() はハンドシェイク書き込み停止中は再送しない (パッチ 032); 証明書の相対 CRL 配布点の完全名は X509 オブジェクトにキャッシュされない (パッチ 029); DTLS は次エポックレコードを最大 16 個までバッファ (パッチ 027); バージョン文字列にタグ `[ipalongpatch_20261102]` が付く (パッチ 033)。

## 11. How to use / 使い方

```
# build the delivered tree exactly like upstream 1.1.1w / 上流 1.1.1w と同じ手順でビルド
tar xzf openssl-1.1.1w-ipalongpatch_20261102-river_lantern.tar.gz && cd openssl-1.1.1w-ipalongpatch_20261102
./config && make && make test
# or apply the patches to a pristine tree / あるいは素のツリーにパッチを適用
tar xzf openssl-1.1.1w.tar.gz && cd openssl-1.1.1w
for p in ../ipalongpatch_info/patch_files_for_each_cve/*.patch; do patch -p1 < "$p"; done
#   (or) patch -p1 < ../ipalongpatch_info/patch_file_consolidated/openssl-1.1.1w_ipalongpatch_consolidated.patch
```

## 12. Notes on the input digests / 入力ダイジェストに関する注記

(EN) src_files_digest_sha256.txt lists regular files only; the .deb packages contain 64 symbolic links (documentation and library links such as libssl.so -> libssl.so.1.1) which have no content of their own and are omitted. The .dsc file is not an archive and appears only in src_archives_digest_sha256.txt. / (JA) src_files_digest_sha256.txt は通常ファイルのみを列挙する。.deb パッケージには 64 本のシンボリックリンク (文書や libssl.so -> libssl.so.1.1 等のライブラリリンク) があるが、固有の内容を持たないため省いた。.dsc はアーカイブではないため src_archives_digest_sha256.txt にのみ現れる。

## 13. Documents / ドキュメント

- docs/20261102_164932_IPALongPatch_Report_Index_openssl-1.1.1w-ipalongpatch_20261102.html - index of all reports / 全レポートの索引
- docs/20261102_164932_Patch001_CVE-2023-5678_DH-large-Q-excessive-time-DoS_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch002_CVE-2024-0727_PKCS12-NULL-ContentInfo-crash_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch003_Marvin-LP2054090_Marvin-RSA-PKCS1-implicit-reject_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch004_CVE-2024-2511_TLS13-session-cache-unbounded_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch005_CVE-2024-4741_SSL-free-buffers-use-after-free_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch006_CVE-2024-5535_SSL-select-next-proto-overread_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch007_CVE-2024-9143_GF2m-poly2arr-OOB-memory-access_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch008_CVE-2024-13176_Minerva-ECDSA-timing-side-chan_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch009_CVE-2025-9230_CMS-PWRI-KEK-unwrap-OOB-rw_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch010_CVE-2025-68160_BIO-f-linebuffer-heap-overflow_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch011_CVE-2025-69418_OCB-AESNI-tail-bytes-unencrypted_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch012_CVE-2025-69419_PKCS12-friendlyName-UTF8-OOB_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch013_CVE-2025-69420_TS-RESP-verify-ASN1-TYPE-check_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch014_CVE-2025-69421_PKCS12-item-decrypt-NULL-deref_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch015_CVE-2026-22795_PKCS12-attr-type-confusion-DoS_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch016_CVE-2026-22796_PKCS7-digest-attr-type-confusion_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch017_CVE-2026-28387_DANE-match-cert-wrong-free-UAF_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch018_CVE-2026-28388_DeltaCRL-no-CRLNumber-NULL-deref_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch019_CVE-2026-28389_CMS-KARI-no-params-NULL-deref_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch020_CVE-2026-28390_CMS-KTRI-OAEP-label-NULL-deref_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch021_CVE-2026-42766_CMS-PWRI-no-KDF-alg-NULL-deref_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch022_CVE-2026-9076_CMS-PWRI-checkbyte-OOB-read_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch023_CVE-2026-7383_ASN1-mbstring-ncopy-int-overflow_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch024_CVE-2026-34180_ASN1-STRING-set-len-truncation_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch025_CVE-2026-45447_PKCS7-verify-use-after-free_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch026_HollowByte_LP2161371-TLS-init-buf-mem-DoS_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch027_CVE-2026-54874_DTLS-future-epoch-buffer-memDoS_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch028_CVE-2026-63072_CMS-AESWRAPPAD-unwrap-OOB-write_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch029_CVE-2026-35189_Relative-CRLDP-excessive-memory_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch030_CVE-2026-54872_EC-ladder-scalar-timing-leak_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch031_CVE-2026-77696_SM2-sig-gen-timing-side-channel_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch032_CVE-2026-84782_DTLS-retransmit-stale-init-off_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/20261102_164932_Patch033_TAGGING_Append-Tag-String-ipalongpatch_20261102_openssl-1.1.1w-ipalongpatch_20261102.md / .html
- docs/*_UserInputPrompt_openssl-1.1.1w-ipalongpatch_20261102.txt - the task prompt verbatim / 入力プロンプト全文
- docs/poc/ - PoC sources and per-item verification reports / PoC ソースと検証レポート
- docs/poc/COMMON.md - the verbatim common instructions given to the verification agents, with a Japanese translation appended / 検証エージェントへの共通指示の原文と日本語訳

## 14. Post-review amendments / レビュー後の修正

(EN) After the first complete assembly of the deliverable (2026/11/02 13:23 JST) it was reviewed by six independent read-only review agents (catalogue consistency, English/Japanese consistency, patch sanity, format rules, per-item documents, source tree), and every finding was re-examined by a sceptical second agent (36 findings, 22 confirmed, 2 refuted, 12 beyond the verification cap and examined by the orchestrator). The following corrections were made; none of them changes the logic of a vulnerability fix. The affected commits were amended in place and the 33 patch files were regenerated.

(JA) 納品物の最初の完全な組み立て (2026/11/02 13:23 JST) の後、6 つの独立した読み取り専用レビューエージェント (目録の整合、英日の整合、パッチの健全性、形式規則、項目別文書、ソースツリー) がレビューし、各指摘を懐疑的な第 2 のエージェントが再検証した (指摘 36 件、確認 22 件、反証 2 件、検証上限超過 12 件は統括セッションが確認)。以下の修正を行った。いずれも脆弱性修正のロジックは変えていない。該当コミットをその場で修正し、33 本のパッチファイルを再生成した。

- **P-02** (EN) Error function codes: five error calls added by patches 001, 002, 004, 008 and 023 reused the function code of a neighbouring function; new codes DH_F_DH_CHECK_PUB_KEY (127), PKCS12_F_PKCS12_UNPACK_P7ENCDATA (134), SSL_F_SSL_SESSION_DUP_INTERN (641), BN_F_BN_MOD_EXP_MONT_FIXED_TOP (153) and ASN1_F_OUT_UTF8 (234) were added following the 1.1.1 conventions (crypto/err/openssl.txt, the public *err.h headers and the *_err.c string tables), so that error messages name the raising function and 'make errors' (util/ck_errf.pl -strict) passes as on pristine 1.1.1w.
  (JA) エラー関数コード: パッチ 001、002、004、008、023 が追加した 5 箇所のエラー呼び出しが隣接関数の関数コードを流用していた。1.1.1 の規約に従い新コード DH_F_DH_CHECK_PUB_KEY (127)、PKCS12_F_PKCS12_UNPACK_P7ENCDATA (134)、SSL_F_SSL_SESSION_DUP_INTERN (641)、BN_F_BN_MOD_EXP_MONT_FIXED_TOP (153)、ASN1_F_OUT_UTF8 (234) を追加 (crypto/err/openssl.txt、公開 *err.h ヘッダ、*_err.c 文字列表) し、エラーメッセージが発生元の関数名を示し、'make errors' (util/ck_errf.pl -strict) が素の 1.1.1w と同様に通るようにした。
- **P-01** (EN) Patch 003: crypto/rsa/rsa_pk1.c now includes rsa_local.h so that the internal prototype of ossl_rsa_padding_check_PKCS1_type_2() is visible ('./config --strict-warnings', which adds -Werror -Wmissing-prototypes, builds again).
  (JA) パッチ 003: crypto/rsa/rsa_pk1.c が rsa_local.h をインクルードし、内部関数 ossl_rsa_padding_check_PKCS1_type_2() のプロトタイプが見えるようにした (-Werror -Wmissing-prototypes を付ける './config --strict-warnings' で再びビルドできる)。
- **PT-03** (EN) Patch 003: in CMS KeyTransRecipientInfo decryption the ctrl that disables implicit rejection is now issued only when the RSA padding mode is PKCS#1 v1.5 and is guarded by OPENSSL_NO_RSA; with RSAES-OAEP recipients the Ubuntu/Red Hat form of the code left two stale errors in the error queue after a successful decryption.
  (JA) パッチ 003: CMS KeyTransRecipientInfo の復号で implicit rejection を無効化する ctrl を、RSA パディングが PKCS#1 v1.5 のときだけ発行し、OPENSSL_NO_RSA でガードした。Ubuntu/Red Hat 形式のコードでは RSAES-OAEP 受信者の復号成功後にエラーキューへ 2 件の無関係なエラーが残っていた。
- **PT-01** (EN) Patch 007: crypto/bn/bn_gf2m.c defines OPENSSL_ECC_MAX_FIELD_BITS (661) as a fallback when <openssl/ec.h> is empty, because in 1.1.1 'no-ec' does not disable ec2m; such builds compile again.
  (JA) パッチ 007: 1.1.1 では 'no-ec' が ec2m を無効化しないため、<openssl/ec.h> が空になる構成向けに crypto/bn/bn_gf2m.c で OPENSSL_ECC_MAX_FIELD_BITS (661) のフォールバック定義を追加し、そのビルドが再びコンパイルできるようにした。
- **P-03** (EN) Patch 029: five comment lines that had been appended to the pristine idp_check_dp() comment outside any IPALongPatch block were moved into the block (rule (13): every change is enclosed by the markers).
  (JA) パッチ 029: 素の idp_check_dp() コメントの末尾に IPALongPatch ブロック外で追記されていた 5 行のコメントをブロック内に移した (規則 (13): すべての変更をマーカで囲む)。
- **P-04 / PT-04** (EN) Patch 032 (test/dtlstest.c): <sys/time.h> is included on Unix for struct timeval / gettimeofday() (e_os.h is not on the include path of that test; strict C89 builds and non-glibc libcs need it), and the BIO_METHOD created by the new fragmenting BIO is released in cleanup_tests() (previously leaked; enable-crypto-mdebug test builds would report it).
  (JA) パッチ 032 (test/dtlstest.c): struct timeval / gettimeofday() のため Unix では <sys/time.h> をインクルード (e_os.h はこのテストのインクルードパスに無く、厳格な C89 や glibc 以外の libc で必要) し、新設の分割 BIO が作る BIO_METHOD を cleanup_tests() で解放するようにした (従来はリークし、enable-crypto-mdebug のテストビルドで報告される)。
- **P-06** (EN) Six code lines longer than 80 columns (patches 014, 027, 032) were wrapped, and the comment blocks of patch 001 were re-wrapped to 79 columns.
  (JA) 80 桁を超えていたコード 6 行 (パッチ 014、027、032) を折り返し、パッチ 001 のコメントブロックを 79 桁に再整形した。
- **P-05** (EN) The header of patch 033 (version tag) no longer claims a Canonical Ubuntu / upstream origin.
  (JA) パッチ 033 (バージョンタグ) のヘッダから Canonical Ubuntu / 上流由来という誤った Origin 記載を除いた。
- **CAT-002 / DOC-01 / DOC-07** (EN) Line ranges in PATCH_LIST.txt and in the per-item documents are now given for the delivered tree (hunk positions mapped through the later patches); deletion-only hunks and ranges touched again by later patches are marked.
  (JA) PATCH_LIST.txt と項目別ドキュメントの行範囲を納品ツリー基準 (後続パッチを通して写像) にし、削除のみの hunk と後続パッチで再変更された範囲に印を付けた。
- **CAT-001** (EN) The assembly script recreates the empty directory wycheproof/ of the original tarball (git archive omits empty directories); the (i)/(ii)/(iii) check was repeated on the delivered tree.
  (JA) 組み立てスクリプトが原本 tarball の空ディレクトリ wycheproof/ を復元するようにした (git archive は空ディレクトリを落とす)。(i)/(ii)/(iii) 検証を納品ツリーで再実施。
- **CAT-003 / CAT-004 / CAT-005 / CAT-006 / ENJA-01..07 / DOC-02..06 / FMT-001 / FMT-002 / FMT-006** (EN) Documentation corrections: file counts (85 files differ from pristine 1.1.1w), the Ubuntu series size (143 patches), the licence wording (OpenSSL License and original SSLeay License), the warning history of patches 029/030, Japanese renderings that were missing (publication histories of items 003/026, PATCH_LIST evidence line, report headings of seven items, index/table headers, COMMON.md), the '001..none' wording, HTML pages completed with all sections and links, section 8 of each item now lists the verification limitations, binary PoC outputs are stored with a .bin suffix, and the empty docs/images/ directory was removed.
  (JA) 文書の修正: ファイル数 (素の 1.1.1w との差分 85 ファイル)、Ubuntu series の本数 (143)、ライセンス表記 (OpenSSL License と original SSLeay License)、パッチ 029/030 の警告履歴、欠けていた日本語 (項目 003/026 の公開経緯、PATCH_LIST の証憑行、7 項目の報告見出し、索引・表の見出し、COMMON.md)、'001..none' の表現、HTML ページへの全節・リンクの収録、各項目 8 節への検証上の制約の記載、バイナリ PoC 出力の .bin 拡張子化、空の docs/images/ の削除。

(EN) Re-verification after the amendments: Linux build 0 warnings (make -j4, 16:31 JST); util/ck_errf.pl -strict -internal: no output, exit 0 (as on pristine 1.1.1w); full test suite: Files=159, Tests=2658, Result: PASS (16:31-16:34 JST); ASan build: rebuilt, exit 0 (16:34 JST); mingw64: x86_64-w64-mingw32 rebuilt, exit 0; openssl.exe version under wine: 'OpenSSL 1.1.1w [ipalongpatch_20261102]  11 Sep 2023' (16:35 JST); wine: 13 recipe files, Files=13, Tests=194, Result: PASS (16:35-16:36 JST); (i)/(ii)/(iii): 33 individual patches and the consolidated patch applied to pristine 1.1.1w without fuzz/offset/rejects; (i) == (ii) and (i) == delivered tree: IDENTICAL, 3108 files + the empty directory wycheproof/ (16:34 JST). The per-item verification logs (001-032) record the PoC runs made before the amendments; the amended code paths were re-checked afterwards and the results are recorded as dated addenda at the end of the affected logs and in section 11 of the 000 log.

(JA) 修正後の再検証: Linux ビルド 0 warnings (make -j4, 16:31 JST); util/ck_errf.pl -strict -internal: no output, exit 0 (as on pristine 1.1.1w); 全テストスイート: Files=159, Tests=2658, Result: PASS (16:31-16:34 JST); ASan ビルド: rebuilt, exit 0 (16:34 JST); mingw64: x86_64-w64-mingw32 rebuilt, exit 0; openssl.exe version under wine: 'OpenSSL 1.1.1w [ipalongpatch_20261102]  11 Sep 2023' (16:35 JST); wine: 13 recipe files, Files=13, Tests=194, Result: PASS (16:35-16:36 JST); (i)/(ii)/(iii): 33 individual patches and the consolidated patch applied to pristine 1.1.1w without fuzz/offset/rejects; (i) == (ii) and (i) == delivered tree: IDENTICAL, 3108 files + the empty directory wycheproof/ (16:34 JST)。項目別の検証ログ (001〜032) には修正前に実施した PoC の記録が入っている。修正したコード経路は修正後に再確認し、その結果を該当ログ末尾の日付付き追記と 000 ログの 11 節に記録した。

## 15. Final tarball verification / 最終 tar.gz の検証

(EN) The deliverable openssl-1.1.1w-ipalongpatch_20261102-river_lantern.tar.gz (SHA-256 8d87d77efa71b642aba522fd57a3967391f21ad2528b31c2b9ac6e920bb96957, 13500364 bytes) was verified after assembly, 2026/11/02 16:50:07 - 2026/11/02 16:52:53 (JST): it was extracted into an empty directory; the extracted source tree without ipalongpatch_info/ was compared with `diff -r` against the result (i) of applying the 33 patches to pristine openssl-1.1.1w (IDENTICAL: no differences, 3108 files and the empty directory wycheproof/ in both); the extracted tree was then configured (`./config shared enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers`), built (configured and built without errors or warnings; 'openssl version' of the built tree prints 'OpenSSL 1.1.1w [ipalongpatch_20261102]  11 Sep 2023') and the complete test suite was run from the extracted copy (All tests successful: Files=159, Tests=2658, Result: PASS). This section was appended after that run, so the final archive differs from the verified one only in this readme.md; the final archive was extracted and compared again (source tree identical to (i)).

(JA) 納品物 openssl-1.1.1w-ipalongpatch_20261102-river_lantern.tar.gz (SHA-256 8d87d77efa71b642aba522fd57a3967391f21ad2528b31c2b9ac6e920bb96957、13500364 バイト) は組み立て後、2026/11/02 16:50:07〜2026/11/02 16:52:53 (JST) に検証した: 空のディレクトリへ展開し、展開したソースツリー (ipalongpatch_info/ を除く) を、素の openssl-1.1.1w に 33 パッチを適用した結果 (i) と `diff -r` で比較 (IDENTICAL: no differences, 3108 files and the empty directory wycheproof/ in both); 展開したツリーを `./config shared enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers` で構成してビルドし (configured and built without errors or warnings; 'openssl version' of the built tree prints 'OpenSSL 1.1.1w [ipalongpatch_20261102]  11 Sep 2023')、展開したコピーから全テストスイートを実行した (All tests successful: Files=159, Tests=2658, Result: PASS)。本節はその実行後に追記したため、最終アーカイブは検証したものと本 readme.md のみが異なる。最終アーカイブも再度展開して比較した (ソースツリーは (i) と同一)。
