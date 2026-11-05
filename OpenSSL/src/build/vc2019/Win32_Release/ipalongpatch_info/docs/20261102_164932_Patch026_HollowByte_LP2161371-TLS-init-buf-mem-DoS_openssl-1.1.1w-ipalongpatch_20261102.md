###### ============================================================
# IPALongPatch [026/033] HollowByte - 'HollowByte' denial of service: handshake message buffer allocated up front for a peer-claimed (huge) message size
# IPALongPatch [026/033] HollowByte - 'HollowByte' DoS: ピアが申告した (巨大な) メッセージ長ぶんのハンドシェイクバッファを前払いで確保

## 0. Resolved vulnerability / 解決した脆弱性

- **Identifier / 識別子:** `HollowByte`  (other IDs / 他の ID: no CVE (OpenSSL treated it as a hardening fix); Ubuntu Launchpad bug #2161371 / USN-8678-2; named 'HollowByte' by the Okta Red Team)
- **Patch / パッチ:** `LP2161371-TLS-init-buf-mem-DoS` (026 of 033) - `ipalongpatch_info/patch_files_for_each_cve/openssl-1.1.1w_ipalongpatch_026of033_HollowByte_LP2161371-TLS-init-buf-mem-DoS.patch`
- **Summary (EN):** Each TLS handshake message carries a 4-byte header (type + 24-bit length). The vulnerable code grew the handshake receive buffer (init_buf) to the full claimed length (up to the max_cert_list limit, 100 KiB by default) as soon as the header had been read, before any body bytes arrived. A remote, unauthenticated attacker sending just the record header plus handshake header (11 bytes) and then stalling forces a disproportionate allocation per connection and, with many connections and allocator fragmentation, memory exhaustion (reported by the Okta Red Team as 'HollowByte'). The fix grows init_buf incrementally as data is actually received.
- **概要 (JA):** TLS ハンドシェイクの各メッセージは 4 バイトのヘッダ (型 + 24 ビット長) を持つ。脆弱なコードはヘッダを読んだ時点で、本体が 1 バイトも届く前に、申告長 (既定では max_cert_list の上限 100 KiB まで) いっぱいまでハンドシェイク受信バッファ (init_buf) を伸長していた。リモートの未認証攻撃者がレコードヘッダ + ハンドシェイクヘッダの 11 バイトだけを送って放置すると、接続ごとに不釣り合いな確保を強制でき、多数の接続とアロケータの断片化によりメモリ枯渇に至る (Okta Red Team が 'HollowByte' として報告)。修正は実際に受信したデータ量に応じて init_buf を段階的に拡張する。
- **Status:** this vulnerability is RESOLVED in openssl-1.1.1w-ipalongpatch_20261102; verification verdict: **PASS** (see section 9). / **状態:** 本脆弱性は openssl-1.1.1w-ipalongpatch_20261102 で解決済み。検証判定: **合格 (PASS)** (9 節参照)。

## 1. Heading / 見出し

- **Document generated / 文書生成日時:** 2026/11/02 16:49:32 (JST)
- **Title (verbatim) / 標題 (原文どおり):** `DNNT 261102_EEHXW5 IPALongPatch openssl-1.1.1w-ipalongpatch_20261102 OpenSSL_1.1.1f_From_Ubuntu`
- **Task (EN):** Back-port the security fixes that Canonical applied to Ubuntu 20.04's openssl 1.1.1f (1.1.1f-1ubuntu2.24+esm6) after the last public OpenSSL 1.1.1 release (1.1.1w, 2023-09-11) onto OpenSSL 1.1.1w, producing openssl-1.1.1w-ipalongpatch_20261102-river_lantern.tar.gz: a complete, buildable source tree with per-vulnerability patches, a consolidated patch, verification logs and this documentation.  This file documents item 026 (HollowByte).
- **タスク (JA):** Canonical が Ubuntu 20.04 の openssl 1.1.1f (1.1.1f-1ubuntu2.24+esm6) に対して、OpenSSL 1.1.1 最後の公開版 (1.1.1w、2023-09-11) より後に適用したセキュリティ修正を OpenSSL 1.1.1w へ移植し、openssl-1.1.1w-ipalongpatch_20261102-river_lantern.tar.gz (単独でビルド可能な完全なソースツリー、脆弱性別パッチ、集約パッチ、検証ログ、本ドキュメント) を作成する。本ファイルは項目 026 (HollowByte) を記録する。
- **Change summary (EN):** ssl/statem/statem.c: grow_init_buf() and its call in read_state_machine() removed.
- **変更概要 (JA):** ssl/statem/statem.c: grow_init_buf() と read_state_machine() 内の呼び出しを除去。

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

- **Identifier / 識別子:** HollowByte; no CVE (OpenSSL treated it as a hardening fix); Ubuntu Launchpad bug #2161371 / USN-8678-2; named 'HollowByte' by the Okta Red Team
- **Title (EN):** 'HollowByte' denial of service: handshake message buffer allocated up front for a peer-claimed (huge) message size
- **標題 (JA):** 'HollowByte' DoS: ピアが申告した (巨大な) メッセージ長ぶんのハンドシェイクバッファを前払いで確保
- **Severity / 深刻度 (EN):** No CVE and no OpenSSL security advisory (the OpenSSL security team classified it as a bug / hardening fix because the per-connection effect is bounded, see the OpenSSL blog post of 2026-07-21). Ubuntu shipped it as 'SECURITY UPDATE: HollowByte Denial of Service issue (LP: #2161371) - No CVE number' (USN-8678-2, 2026-08-25).
- **深刻度 (JA):** CVE も OpenSSL セキュリティアドバイザリも無し (接続あたりの影響が有界なため OpenSSL セキュリティチームはバグ/堅牢化修正として扱った、2026-07-21 の OpenSSL ブログ参照)。Ubuntu は 'SECURITY UPDATE: HollowByte Denial of Service issue (LP: #2161371) - No CVE number' として配布 (USN-8678-2、2026-08-25)。
- **Publication / 公開日:** Upstream fix merged 2026-04-17 (PR #30792/#30793/#30794), released silently in OpenSSL 4.0.1/3.6.3/3.5.7/3.4.6/3.0.21 (2026-06-09); Okta Red Team write-up 2026-07-16; OpenSSL blog 2026-07-21; Ubuntu LP #2161371 2026-07-20, focal esm5 2026-08-25 / 上流修正のマージ 2026-04-17 (PR #30792/#30793/#30794)、OpenSSL 4.0.1/3.6.3/3.5.7/3.4.6/3.0.21 でサイレントにリリース (2026-06-09); Okta Red Team の記事 2026-07-16; OpenSSL ブログ 2026-07-21; Ubuntu LP #2161371 2026-07-20、focal esm5 2026-08-25
- **Summary (EN):** Each TLS handshake message carries a 4-byte header (type + 24-bit length). The vulnerable code grew the handshake receive buffer (init_buf) to the full claimed length (up to the max_cert_list limit, 100 KiB by default) as soon as the header had been read, before any body bytes arrived. A remote, unauthenticated attacker sending just the record header plus handshake header (11 bytes) and then stalling forces a disproportionate allocation per connection and, with many connections and allocator fragmentation, memory exhaustion (reported by the Okta Red Team as 'HollowByte'). The fix grows init_buf incrementally as data is actually received.
- **概要 (JA):** TLS ハンドシェイクの各メッセージは 4 バイトのヘッダ (型 + 24 ビット長) を持つ。脆弱なコードはヘッダを読んだ時点で、本体が 1 バイトも届く前に、申告長 (既定では max_cert_list の上限 100 KiB まで) いっぱいまでハンドシェイク受信バッファ (init_buf) を伸長していた。リモートの未認証攻撃者がレコードヘッダ + ハンドシェイクヘッダの 11 バイトだけを送って放置すると、接続ごとに不釣り合いな確保を強制でき、多数の接続とアロケータの断片化によりメモリ枯渇に至る (Okta Red Team が 'HollowByte' として報告)。修正は実際に受信したデータ量に応じて init_buf を段階的に拡張する。
- **Technical detail (EN):** In 1.1.1w ssl/statem/statem.c read_state_machine() called grow_init_buf(s, message_size + SSL3_HM_HEADER_LENGTH) right after tls_get_message_header(); the fix moves grow_init_buf() into ssl/statem/statem_lib.c tls_get_message_body() and grows the buffer before each read of at most SSL3_RT_MAX_PLAIN_LENGTH (16 KiB) bytes, re-reading s->init_msg after each possible reallocation.
- **技術的詳細 (JA):** 1.1.1w の ssl/statem/statem.c read_state_machine() は tls_get_message_header() の直後に grow_init_buf(s, message_size + SSL3_HM_HEADER_LENGTH) を呼んでいた。修正は grow_init_buf() を ssl/statem/statem_lib.c tls_get_message_body() に移し、最大 SSL3_RT_MAX_PLAIN_LENGTH (16 KiB) ずつの読み取りの前にバッファを拡張し、再確保の可能性があるため毎回 s->init_msg を再取得する。
- **Affected versions (EN):** All OpenSSL versions before 4.0.1 / 3.6.3 / 3.5.7 / 3.4.6 / 3.0.21 (TLS; DTLS handled differently). 1.1.1 extended-support releases receive the change through the vendor's channel (no public 1.1.1 commit); 1.1.1w is affected.
- **影響バージョン (JA):** 4.0.1 / 3.6.3 / 3.5.7 / 3.4.6 / 3.0.21 より前の全 OpenSSL (TLS; DTLS は扱いが異なる)。1.1.1 の延長サポート版はベンダ経由で変更を受け取る (公開された 1.1.1 コミットは無い)。1.1.1w は影響を受ける。

## 4-2. References / 参考 URL

| URL | Title (EN) / 題名 (JA) | Published / 発行日 | Author / 作者・発行者 | Accessed / 閲覧日 |
|---|---|---|---|---|
| https://sec.okta.com/articles/2026/06/openssl-hollowbtye-a-dos-hiding-in-11-bytes/ | OpenSSL HollowByte: A DoS Hiding in 11 Bytes / OpenSSL HollowByte: 11 バイトに潜む DoS | 2026-07-16 | Okta Red Team | 2026-11-02 (JST) |
| https://openssl-library.org/post/2026-07-21-hollowbyte/ | On the "HollowByte" denial-of-service report / 「HollowByte」DoS 報告について | 2026-07-21 | OpenSSL Library | 2026-11-02 (JST) |
| https://github.com/openssl/openssl/pull/30794 | Grow the init_buf incrementally as we receive data (3.0 backport) #30794 / 受信に応じて init_buf を段階的に拡張する (3.0 バックポート) #30794 | 2026-04-13 | Matt Caswell (OpenSSL) | 2026-11-02 (JST) |
| https://bugs.launchpad.net/bugs/2161371 | Bug #2161371 'OpenSSL HollowByte DoS' / Launchpad バグ #2161371 'OpenSSL HollowByte DoS' | 2026-07-20 | Launchpad (Richard Laager) | 2026-11-02 (JST) |
| https://ubuntu.com/security/notices/USN-8678-2 | USN-8678-2: OpenSSL, OpenSSL 1.0 vulnerabilities / USN-8678-2: OpenSSL, OpenSSL 1.0 の脆弱性 | 2026-08-25 | Canonical | 2026-11-02 (JST) |
| https://www.bleepingcomputer.com/news/security/hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload/ | HollowByte DDoS flaw bloats OpenSSL server memory with 11-byte payload / HollowByte DDoS 欠陥が 11 バイトのペイロードで OpenSSL サーバのメモリを膨張させる | 2026-07-17 | Bill Toulas (BleepingComputer) | 2026-11-02 (JST) |
| https://atmarkit.itmedia.co.jp/ait/spv/2607/22/news042.html | A new DoS attack on OpenSSL that pressures memory with only 11 bytes (Japanese) / わずか11バイトでメモリを圧迫 OpenSSLを狙う新DoS攻撃、その意外な仕組み | 2026-07-22 | @IT (ITmedia) | 2026-11-02 (JST) |

- (EN) Input reference files (local): openssl_1.1.1f-1ubuntu2.24+esm6.debian.tar.xz (debian/patches, debian/changelog), openssl_1.1.1f.orig.tar.gz, openssl-1.1.1w.tar.gz, libssl1.1 / libssl-dev / openssl .deb packages (used to confirm the vendor, version and build options).
- (JA) 入力参考ファイル (ローカル): openssl_1.1.1f-1ubuntu2.24+esm6.debian.tar.xz (debian/patches、debian/changelog)、openssl_1.1.1f.orig.tar.gz、openssl-1.1.1w.tar.gz、libssl1.1 / libssl-dev / openssl の .deb パッケージ (ベンダ・バージョン・ビルドオプションの確認に使用)。

## 4-3. Acknowledgements and copyright / 謝辞および著作権表記

- (EN) Upstream fix 'Grow the init_buf incrementally as we receive data' by Matt Caswell (OpenSSL Foundation; commit c5785a5e35882079faf49015c0ea0bb1b9a24ecf / PR #30794 for 3.0), reviewed by Nikola Pajkovsky and Tomas Mraz; issue reported by the Okta Red Team. Ubuntu backport debian/patches/lp2161371.patch (Leonidas Da Silva Barbosa / Marc Deslauriers, Canonical). OpenSSL copyright and licence as for item 001.
- (JA) 上流修正 'Grow the init_buf incrementally as we receive data' は Matt Caswell 氏 (OpenSSL Foundation; コミット c5785a5e35882079faf49015c0ea0bb1b9a24ecf / 3.0 向け PR #30794)、レビューは Nikola Pajkovsky、Tomas Mraz 各氏、報告は Okta Red Team。Ubuntu バックポート debian/patches/lp2161371.patch (Leonidas Da Silva Barbosa 氏 / Marc Deslauriers 氏、Canonical)。OpenSSL の著作権・ライセンス表示は項目 001 と同じ。
- (EN) This port, its comments and this documentation were produced by the IPALongPatch process with generative AI (see section 3); the resulting source files remain subject to the OpenSSL licence of the 1.1.1 series (LICENSE file in the tree).
- (JA) 本移植、そのコメント、本ドキュメントは生成 AI による IPALongPatch 工程で作成した (3 節参照)。結果のソースファイルは引き続き 1.1.1 系の OpenSSL ライセンス (ツリー内 LICENSE ファイル) に従う。

## 5. Source code reading summary / 入力ソースコード読解結果

- (EN) ssl/statem/statem.c (1.1.1w): static grow_init_buf() and the call in read_state_machine() guarded by '!SSL_IS_DTLS(s) && s->s3->tmp.message_size > 0' ('dtls_get_message already did this'); ssl/statem/statem_lib.c tls_get_message_body() reads 'n = message_size - init_num' bytes in one loop into p = s->init_msg. Identical to 1.1.1f; tls_get_message_header() already limits the length to s->max_cert_list.
- (JA) 1.1.1w の ssl/statem/statem.c: static grow_init_buf() と、read_state_machine() 内の '!SSL_IS_DTLS(s) && s->s3->tmp.message_size > 0' ('dtls_get_message already did this') で守られた呼び出し; ssl/statem/statem_lib.c tls_get_message_body() は 'n = message_size - init_num' バイトを 1 つのループで p = s->init_msg に読む。1.1.1f と同一; tls_get_message_header() は既に長さを s->max_cert_list に制限している。

## 6. Work performed (patching and testing) / 実施したパッチ当て・テスト作業

- (EN) Method common to all items: the Ubuntu patch was read in full and compared with the 1.1.1w sources (semantic review, not mechanical application); the change was re-applied with an exact-match replacement script (/home/user/work/port/026_*.py in the verification environment) or, for very large patches, applied with patch(1) and then adapted; every modified region was wrapped in '/* IPALongPatch: openssl-1.1.1w-ipalongpatch_20261102 --- PATCH_BEGIN --- ... */' and '--- PATCH_END ---' comment blocks (using the comment style of the file: C block comments, '#' for Perl/test data); the tree was rebuilt incrementally after each patch (0 compiler warnings in the final state of each patch; see section 2 of the 000 log), the relevant test recipes were run, and after the last patch the complete test suite was run on Linux (159 recipe files, 2658 tests, PASS) and a Windows x86_64 cross build (mingw64) was built and partly tested under wine (13 recipe files, 194 tests, PASS); the whole chain was repeated after the post-review amendments (readme.md section 14).
- (JA) 全項目共通の方法: Ubuntu パッチを全文精読し 1.1.1w のソースと突合 (機械的適用ではなく意味的なレビュー); 変更は厳密一致置換スクリプト (検証環境の /home/user/work/port/026_*.py) で再適用、または非常に大きなパッチは patch(1) で適用後に調整; 変更箇所はすべて '/* IPALongPatch: openssl-1.1.1w-ipalongpatch_20261102 --- PATCH_BEGIN --- ... */' と '--- PATCH_END ---' のコメントブロックで囲んだ (ファイルの慣習に従い C のブロックコメント、Perl/テストデータは '#'); 各パッチ後にツリーを増分ビルド (各パッチの最終状態でコンパイラ警告 0; 000 ログの 2 節参照) し関連テストレシピを実行、最終パッチ後に Linux で全テストスイート (159 レシピファイル、2658 テスト、PASS) を実行し、Windows x86_64 クロスビルド (mingw64) をビルドして wine 上で一部テスト (13 レシピファイル、194 テスト、PASS) を実施した。レビュー後の修正 (readme.md 14 節) の後に同じ一連の確認を繰り返した。
- (EN) Item specific: Applied by exact-match replacement (script 026_HollowByte.py) with markers; build 0 warnings; test_ssl_new, test_sslapi and the full suite pass (large Certificate messages spanning several records are exercised by the suite). The PoC sends the 11-byte prefix to a TLS server and measures the init_buf growth (gdb on BUF_MEM_grow_clean / heap statistics): ~100 KiB in the unpatched build versus at most 16 KiB steps in the patched build.
- (JA) 項目固有: 厳密一致置換 (スクリプト 026_HollowByte.py) で適用しマーカ付加。ビルド警告 0、test_ssl_new、test_sslapi と全テスト合格 (複数レコードにまたがる大きな Certificate メッセージはスイートで実行される)。PoC は TLS サーバへ 11 バイトのプレフィックスを送り init_buf の伸長を計測 (BUF_MEM_grow_clean への gdb / ヒープ統計): 未パッチ版は約 100 KiB、パッチ版は最大 16 KiB 刻み。

## 7. Concrete changes to the target source / 具体的な変更点

- (EN) ssl/statem/statem.c: grow_init_buf() and its call in read_state_machine() removed. ssl/statem/statem_lib.c: grow_init_buf() added; tls_get_message_body() reads in chunks of at most SSL3_RT_MAX_PLAIN_LENGTH, calling grow_init_buf(s, init_num + chunk + SSL3_HM_HEADER_LENGTH) before each read and refreshing p = s->init_msg.
- (JA) ssl/statem/statem.c: grow_init_buf() と read_state_machine() 内の呼び出しを除去。ssl/statem/statem_lib.c: grow_init_buf() を追加し、tls_get_message_body() は最大 SSL3_RT_MAX_PLAIN_LENGTH ずつ読み、各読み取り前に grow_init_buf(s, init_num + chunk + SSL3_HM_HEADER_LENGTH) を呼び p = s->init_msg を更新する。

Files, line ranges (in the delivered tree, including the IPALongPatch comment blocks) and enclosing functions / 変更ファイル・行範囲 (納品ツリー、IPALongPatch コメントブロックを含む)・包含関数:

| File / ファイル | Lines (delivered tree) / 行範囲 (納品ツリー) | Function(s) / 関数 |
|---|---|---|
| ssl/statem/statem.c | 497-518, 615-641 | init_read_state_machine(); read_state_machine() |
| ssl/statem/statem_lib.c | 1260-1296, 1299-1321, 1331-1371, 1373, 1380, 1382 | tls_get_message_body(); tls_get_message_header() |

Patch file / パッチファイル: `ipalongpatch_info/patch_files_for_each_cve/openssl-1.1.1w_ipalongpatch_026of033_HollowByte_LP2161371-TLS-init-buf-mem-DoS.patch` (apply with `patch -p1` from the top of the openssl-1.1.1w tree after patches 001..025 / openssl-1.1.1w ツリーの最上位で、001..025 のパッチの後に `patch -p1` で適用).

## 8. Constraints, concerns and remaining issues / 制約事項・懸念事項・残課題

- (EN) The incremental growth uses BUF_MEM_grow_clean() (realloc) several times for large messages; this is the upstream design. DTLS is not covered by this change (upstream left DTLS as future work). The remaining 'slow connection' exposure is a general server configuration matter (timeouts, connection limits).
- (JA) 段階的拡張は大きなメッセージでは BUF_MEM_grow_clean() (realloc) を複数回行うが、これは上流の設計。DTLS は本変更の対象外 (上流も今後の課題としている)。残る『遅い接続』のリスクは一般的なサーバ設定 (タイムアウト、接続数制限) の問題。
- (EN) General: the verification environment is a 4 vCPU Linux x86_64 VM; builds for other CPUs/OSes (ARM, PowerPC, s390x, macOS, VMS...) could not be executed, but all changes are plain C89-compatible code taken from the upstream/vendor patches, and the Windows build was verified with mingw64 + wine. Timing side-channel items are verified structurally plus with best-effort statistics.
- (JA) 一般: 検証環境は 4 vCPU の Linux x86_64 VM であり、他の CPU/OS (ARM、PowerPC、s390x、macOS、VMS 等) でのビルドは実行できなかったが、全変更は上流/ベンダパッチ由来の素の C89 互換コードであり、Windows ビルドは mingw64 + wine で検証した。タイミングサイドチャネル項目は構造的検証と可能な範囲の統計で検証した。
- (EN) Verification limitations (from the PoC verification of this item, see section 9): Per-connection effect is bounded (~170 KiB); no CVE assigned. The glibc fragmentation / RSS retention described by the reporter was not reproduced; the PoC quantifies the per-connection allocation precisely instead. DTLS is out of scope of the fix.
- (JA) 検証上の制約 (本項目の PoC 検証より、9 節参照): 接続あたりの影響は有界 (約 170 KiB) で CVE は未割り当て。報告者が述べる glibc 断片化/RSS 高止まりは再現せず、PoC は接続あたりの確保量を正確に定量化した。DTLS は修正の対象外。

## 9. Verification results / 検証結果

- **Verdict / 判定:** **PASS** (合格)
- **Start / 開始:** 2026/11/02 12:33:08 (JST)  **End / 終了:** 2026/11/02 13:10:57 (JST)  **Duration / 所要時間:** 00:37:49
- **Log file / ログファイル:** `ipalongpatch_info/logs/20261102_123308_026of033_HollowByte_LP2161371-TLS-init-buf-mem-DoS.log`  (contains the environment information, every command, raw outputs, gdb/ASan/valgrind evidence and the final verdict / 環境情報、全コマンド、生の出力、gdb/ASan/valgrind の証拠、最終判定を収録)
- **Method (EN):** Python client sends 9-byte 'HollowByte' headers on N idle TCP connections; C server measures mallinfo2/VmRSS/VmData before and after the header is processed; stock openssl s_server of each build run under gdb with a conditional breakpoint on BUF_MEM_grow_clean; s_client/s_server regression including a 25-certificate chain.
- **方法 (JA):** Python クライアントが N 本の放置 TCP 接続に 9 バイトの 'HollowByte' ヘッダを送信; C サーバがヘッダ処理前後の mallinfo2/VmRSS/VmData を計測; 各ビルドの標準 openssl s_server を BUF_MEM_grow_clean への条件付きブレークポイント付き gdb で実行; 25 証明書チェーンを含む s_client/s_server 回帰。
- **Before the patch (EN):** 200 connections sending only a 9-byte record+handshake header claiming a 131072-byte ClientHello: heap +154,272 bytes per connection (+30.9 MB total, VmRSS 14.5->41.2 MB); gdb on s_server: BUF_MEM_grow_clean(len=131076) -> 174,772-byte allocation from read_state_machine()/grow_init_buf() before any body byte.
- **パッチ前 (JA):** 131072 バイトの ClientHello を申告する 9 バイトのレコード+ハンドシェイクヘッダだけを送る 200 接続: 接続あたりヒープ +154,272 バイト (合計 +30.9 MB、VmRSS 14.5→41.2 MB); s_server の gdb: 本体未着のまま read_state_machine()/grow_init_buf() から BUF_MEM_grow_clean(len=131076) → 174,772 バイト確保。
- **After the patch (EN):** Patched: 0 bytes of heap growth per connection for the same traffic (VmRSS/VmData unchanged); gdb: only BUF_MEM_grow_clean(len=16388) from tls_get_message_body(), satisfied by the existing 21848-byte buffer; ASan builds clean.
- **パッチ後 (JA):** 修正版: 同じトラフィックで接続あたりヒープ増加 0 バイト (VmRSS/VmData 不変); gdb: tls_get_message_body() からの BUF_MEM_grow_clean(len=16388) のみで既存の 21848 バイトバッファで賄われる; ASan ビルドもクリーン。
- **Regression / side-effect check (EN):** TLS 1.2/1.3 handshakes with HTTP 200 and 21,758/21,811-byte Certificate messages spanning several records are received correctly by the patched client from patched and unpatched servers (and by the unpatched client from the patched server).
- **回帰・副作用確認 (JA):** TLS 1.2/1.3 ハンドシェイクで HTTP 200 を取得し、複数レコードにまたがる 21,758/21,811 バイトの Certificate メッセージを修正版クライアントが修正版/未修正サーバから (未修正クライアントも修正版サーバから) 正しく受信。
- **Limitations (EN):** Per-connection effect is bounded (~170 KiB); no CVE assigned. The glibc fragmentation / RSS retention described by the reporter was not reproduced; the PoC quantifies the per-connection allocation precisely instead. DTLS is out of scope of the fix.
- **制約 (JA):** 接続あたりの影響は有界 (約 170 KiB) で CVE は未割り当て。報告者が述べる glibc 断片化/RSS 高止まりは再現せず、PoC は接続あたりの確保量を正確に定量化した。DTLS は修正の対象外。
- **Tools / 使用ツール:** python3 -I (TCP client), gcc, mallinfo2/proc status, gdb, AddressSanitizer, openssl s_server/s_client -msg, bash
- **PoC files / PoC ファイル (copied into ipalongpatch_info/docs/poc/ unless marked / 印の無いものは収録済み):** `ipalongpatch_info/docs/poc/026_HollowByte/hb_client.py`, `ipalongpatch_info/docs/poc/026_HollowByte/hb_server.c`, `ipalongpatch_info/docs/poc/026_HollowByte/gdb_bufgrow.cmd`, `ipalongpatch_info/docs/poc/026_HollowByte/run_poc.sh`, `ipalongpatch_info/docs/poc/026_HollowByte/regress.sh`, `ipalongpatch_info/docs/poc/026_HollowByte/make_deliverables.py`, `ipalongpatch_info/docs/poc/026_HollowByte/mkdeliv.py`, `ipalongpatch_info/docs/poc/026_HollowByte/out/`
- (EN) Whole-tree checks that cover this item too: the complete OpenSSL test suite on the final tree (Linux, 2658 tests, PASS), the mingw64 Windows build with 194 tests under wine (PASS), the ASan builds used by the PoC, and the (i)/(ii)/(iii) patch consistency check, all repeated after the post-review amendments - see ipalongpatch_info/logs/*_000of033_ALL_Build-and-test-suite-Linux-and-Windows.log and readme.md (sections 8, 9 and 14).
- (JA) 本項目にも関わるツリー全体の確認: 最終ツリーでの OpenSSL 全テストスイート (Linux、2658 テスト、PASS)、mingw64 Windows ビルドの wine 上 194 テスト (PASS)、PoC に用いた ASan ビルド、(i)/(ii)/(iii) パッチ一致検証。いずれもレビュー後の修正の後に再実施 - ipalongpatch_info/logs/*_000of033_ALL_Build-and-test-suite-Linux-and-Windows.log と readme.md (8、9、14 節) 参照。

### 9-1. Detailed verification report (PoC design, evidence excerpts, manual reproduction) / 詳細検証レポート (PoC 設計・証拠抜粋・手動再現手順)

The following report was written during the verification; paths refer to the verification environment (/home/user/work/...) and the PoC sources are included under ipalongpatch_info/docs/poc/. / 以下は検証時に作成したレポートである。パスは検証環境 (/home/user/work/...) のものであり、PoC のソースは ipalongpatch_info/docs/poc/ に収録している。

## 026/033 HollowByte — LP2161371-TLS-init-buf-mem-DoS

Log file / ログファイル: `20261102_123308_026of033_HollowByte_LP2161371-TLS-init-buf-mem-DoS.log` (in /home/user/work/deliver/ipalongpatch_info/logs/). Verification 2026/11/02 12:33:08–2026/11/02 13:10:57 (JST), verdict **PASS**.

ログファイル: `20261102_123308_026of033_HollowByte_LP2161371-TLS-init-buf-mem-DoS.log` (/home/user/work/deliver/ipalongpatch_info/logs/ 配下)。検証 2026/11/02 12:33:08〜2026/11/02 13:10:57 (JST)、判定 **PASS**。

### Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コード上の観察)

'HollowByte' (no CVE; Ubuntu LP: #2161371; upstream PR #30792-#30794 'Grow the init_buf incrementally as we receive data', OpenSSL 3.0.21 etc.): every TLS handshake message starts with a 4 byte header (1 byte type, 24 bit length). In 1.1.1w, as soon as the header has been read, read_state_machine() (ssl/statem/statem.c:610) calls grow_init_buf(s, message_size + 4) -> BUF_MEM_grow_clean(), which immediately (re)allocates the handshake buffer for the whole announced length - up to CLIENT_HELLO_MAX_LENGTH = 131396 bytes for a ClientHello - before any body byte has arrived (BUF_MEM_grow_clean even over-allocates by 4/3: a claimed 131072 bytes become a 174772 byte allocation). An unauthenticated peer therefore makes the server allocate ~170 KiB per connection by sending 9 bytes (TLS record header + handshake header) and then nothing; with many such idle connections this exhausts memory (denial of service, worsened by glibc heap fragmentation as described by the reporter).

「HollowByte」(CVE 無し; Ubuntu LP: #2161371; 上流 PR #30792〜#30794 'Grow the init_buf incrementally as we receive data'、OpenSSL 3.0.21 等): TLS ハンドシェイクメッセージはすべて 4 バイトのヘッダ (型 1 バイト、長さ 24 ビット) で始まる。1.1.1w では、ヘッダを読んだ直後に read_state_machine() (ssl/statem/statem.c:610) が grow_init_buf(s, message_size + 4) → BUF_MEM_grow_clean() を呼び、本体が 1 バイトも届く前に申告長全体 — ClientHello なら最大 CLIENT_HELLO_MAX_LENGTH = 131396 バイト — のハンドシェイクバッファを即座に (再) 確保する (BUF_MEM_grow_clean はさらに 4/3 倍に過剰確保する: 申告 131072 バイトが 174772 バイトの確保になる)。そのため認証されていない相手が 9 バイト (TLS レコードヘッダ + ハンドシェイクヘッダ) だけ送って何も送らないことで、サーバに接続あたり約 170 KiB を確保させられる; そのような放置接続を多数作るとメモリが枯渇する (DoS; 報告者が述べるとおり glibc のヒープ断片化で悪化する)。

### PoC design / PoC の設計

hb_client.py (python3 -I) opens N TCP connections to 127.0.0.1 and sends on each exactly 9 bytes: 16 03 01 00 04 (record header, length 4) + 01 02 00 00 (ClientHello header claiming 131072 bytes), then keeps the connections open. hb_server.c is a non-blocking TLS server that accepts N connections, calls SSL_accept() once per connection (P1: fixed per-connection cost, no data yet), then calls SSL_accept() again when the 9 bytes arrive (P2) and reports heap in use (mallinfo2 uordblks+hblkhd), VmRSS and VmData at each point; the P2-P1 difference divided by N is the memory the 9 byte header costs per connection: expected ~150 KiB unpatched and ~0 patched (the initial 16 KiB init_buf, allocated as 21849 bytes by BUF_MEM_grow, already covers the first 16388 byte chunk). N = 200 for the debug builds, 100 for the ASan builds (RSS only; mallinfo2 is meaningless under ASan). Second, deterministic structural evidence on the stock 'openssl s_server' of each build under gdb: 'break BUF_MEM_grow_clean if len >= 16000' (set after 'break main' so the shared library symbol is resolved; stdin kept open because s_server quits on stdin EOF) prints the requested length and the backtrace for one HollowByte connection: unpatched 131076 from read_state_machine()/grow_init_buf(), patched 16388 from tls_get_message_body(). Regression (regress.sh): normal TLS 1.2 and 1.3 handshakes plus a 25 certificate chain (20112 bytes DER; Certificate message 21758/21811 bytes, i.e. spanning several records) received by the patched client from patched and unpatched servers, and by the unpatched client from the patched server; HTTP 200 must be obtained via s_server -www.

hb_client.py (python3 -I) は 127.0.0.1 に N 本の TCP 接続を開き、それぞれに正確に 9 バイト: 16 03 01 00 04 (レコードヘッダ、長さ 4) + 01 02 00 00 (131072 バイトを申告する ClientHello ヘッダ) を送って接続を開いたまま保持する。hb_server.c は非ブロッキングの TLS サーバで、N 接続を accept し、接続ごとに SSL_accept() を 1 回呼び (P1: データ未着時の固定コスト)、9 バイトが届いたら再度 SSL_accept() を呼ぶ (P2)。各時点でヒープ使用量 (mallinfo2 uordblks+hblkhd)、VmRSS、VmData を報告し、P2−P1 を N で割った値が 9 バイトのヘッダが接続あたりに課すメモリ: 期待値は未修正で約 150 KiB、修正版で約 0 (BUF_MEM_grow が 21849 バイトで確保した初期 16 KiB の init_buf が最初の 16388 バイトチャンクを既に賄う)。デバッグビルドは N = 200、ASan ビルドは 100 (RSS のみ; ASan 下では mallinfo2 は無意味)。第二に、各ビルドの標準 'openssl s_server' に gdb を付けた決定的な構造的証拠: 'break BUF_MEM_grow_clean if len >= 16000' ('break main' 後に設定して共有ライブラリのシンボルを解決; s_server は stdin EOF で終了するため stdin を維持) が HollowByte 接続 1 本に対する要求長とバックトレースを表示: 未修正は read_state_machine()/grow_init_buf() からの 131076、修正版は tls_get_message_body() からの 16388。回帰 (regress.sh): 通常の TLS 1.2/1.3 ハンドシェイクと、25 証明書のチェーン (DER 20112 バイト; Certificate メッセージ 21758/21811 バイトで複数レコードにまたがる) を修正版クライアントが修正版/未修正サーバから、未修正クライアントが修正版サーバから受信し、s_server -www で HTTP 200 を得ること。

### Observed behaviour BEFORE the patch (evidence excerpts) / 修正前の挙動 (証拠の抜粋)

```
P1 all connections accepted, SSL_accept() called, no data yet: heap_in_use=  14654672 bytes  VmRSS=  14260 kB  VmData=  14536 kB
   per-connection fixed cost: 72428 bytes
P2 every connection delivered its 9 byte header, SSL_accept() -> WANT_READ: heap_in_use=  45509072 bytes  VmRSS=  40936 kB  VmData=  48936 kB
   heap growth caused by the 9 byte headers: 30854400 bytes total = 154272 bytes per connection
RESULT: per-connection growth after the header = 154272 bytes (VULNERABLE: init_buf pre-allocated to the claimed size)
HIT 1: BUF_MEM_grow_clean(str->max=21848, len=131076) -> allocation will be (len+3)/3*4 = 174772 bytes
#0  BUF_MEM_grow_clean (str=0x5555556e1770, len=131076) at crypto/buffer/buffer.c:115
#1  0x00007ffff7f67aee in grow_init_buf (s=0x55555570cb00, size=131076) at ssl/statem/statem.c:501
#2  0x00007ffff7f67d9b in read_state_machine (s=0x55555570cb00) at ssl/statem/statem.c:610
```

Unpatched: 9 bytes per connection cost 154,272 bytes of heap each (200 connections: +30.9 MB heap, VmRSS 14.5 -> 41.2 MB); gdb shows BUF_MEM_grow_clean(len=131076) -> 174,772 byte allocation from read_state_machine() right after the header.

未修正: 接続あたり 9 バイトで各 154,272 バイトのヒープを消費 (200 接続: ヒープ +30.9 MB、VmRSS 14.5 → 41.2 MB); gdb はヘッダ直後に read_state_machine() から BUF_MEM_grow_clean(len=131076) → 174,772 バイト確保を示す。

### Observed behaviour AFTER the patch / 修正後の挙動

```
P1 all connections accepted, SSL_accept() called, no data yet: heap_in_use=  14654800 bytes  VmRSS=  14232 kB  VmData=  14536 kB
   per-connection fixed cost: 72428 bytes
P2 every connection delivered its 9 byte header, SSL_accept() -> WANT_READ: heap_in_use=  14654800 bytes  VmRSS=  14240 kB  VmData=  14536 kB
   heap growth caused by the 9 byte headers: 0 bytes total = 0 bytes per connection
RESULT: per-connection growth after the header = 0 bytes (OK: buffer grows only with received data)
HIT 1: BUF_MEM_grow_clean(str->max=21848, len=16388) -> allocation will be (len+3)/3*4 = 21852 bytes
#0  BUF_MEM_grow_clean (str=0x5555556e17e0, len=16388) at ../openssl-1.1.1w-ipalongpatch_20261102/crypto/buffer/buffer.c:115
#1  0x00007ffff7f778b2 in grow_init_buf (s=0x55555570cb70, size=16388) at ../openssl-1.1.1w-ipalongpatch_20261102/ssl/statem/statem_lib.c:1285
#2  0x00007ffff7f779b0 in tls_get_message_body (s=0x55555570cb70, len=0x7fffffffb658) at ../openssl-1.1.1w-ipalongpatch_20261102/ssl/statem/statem_lib.c:1364
```

Patched: 0 bytes of growth per connection (RSS/VmData unchanged); the only grow request is 16388 bytes from tls_get_message_body(), satisfied by the existing buffer.

修正版: 接続あたり増加 0 バイト (RSS/VmData 不変); 拡張要求は tls_get_message_body() からの 16388 バイトのみで既存バッファで賄われる。

### Regression check / 回帰確認

```
chain file: 25 certificates, 20112 bytes of DER in total (> 16384 => Certificate message spans several records)
(a) normal handshakes, patched server + patched client
[tls12_small] New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384; HTTP 200: 1; Certificate handshake message: 819 bytes
[tls13_small] New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384; HTTP 200: 1; Certificate handshake message: 822 bytes
(b) big chain: patched client receiving a Certificate message > 16 KiB (multi-record)
[tls12_bigchain_pp] New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384; HTTP 200: 1; Certificate handshake message: 21758 bytes
21758
[tls13_bigchain_pp] New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384; HTTP 200: 1; Certificate handshake message: 21811 bytes
21811
[tls12_bigchain_bp] New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384; HTTP 200: 1; Certificate handshake message: 21758 bytes
21758
(c) big chain: patched server, unpatched client (interoperability)
[tls13_bigchain_pb] New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384; HTTP 200: 1; Certificate handshake message: 21811 bytes
21811
Certificate message sizes seen by the clients (TLS1.2 p/p, TLS1.3 p/p, TLS1.2 base-server/patched-client, TLS1.3 patched-server/base-client): 21758 21811 21758 21811 bytes
REGRESSION: PASS
```

Normal TLS 1.2/1.3 handshakes and multi-record Certificate messages (21.7 KB) work with the patched client/server in all combinations; the patched tree's test suite (test_ssl_new etc.) was reported passing by the build step.

通常の TLS 1.2/1.3 ハンドシェイクと複数レコードにまたがる Certificate メッセージ (21.7 KB) は修正版クライアント/サーバの全組み合わせで動作; 修正版ツリーのテストスイート (test_ssl_new 等) はビルド工程で合格済みと報告されている。

### How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```
cd /home/user/work/poc/026_HollowByte
./run_poc.sh                                 # everything, prints VERDICT
## manual measurement (terminal 1 / terminal 2):
./hb_server_base 14026 200 /home/user/work/src_1.1.1w/openssl-1.1.1w/test/certs/servercert.pem /home/user/work/src_1.1.1w/openssl-1.1.1w/test/certs/serverkey.pem
python3 -I hb_client.py 127.0.0.1 14026 200 131072 4 2        # -> RESULT: per-connection growth after the header = 154272 bytes (base) / 0 (hb_server_patched)
## gdb on the stock server:
sleep 40 | LD_LIBRARY_PATH=/home/user/work/base/openssl-1.1.1w timeout 30 gdb -batch -x gdb_bufgrow.cmd --args /home/user/work/base/openssl-1.1.1w/apps/openssl s_server -accept 14126 -cert <cert> -key <key> &
python3 -I hb_client.py 127.0.0.1 14126 1 131072 3 1          # -> HIT 1: BUF_MEM_grow_clean(..., len=131076) (base) / len=16388 (patched)
./regress.sh /home/user/work/patched/build /home/user/work/base/openssl-1.1.1w 14226
```

Build example (BASE): gcc -g -O0 -I/home/user/work/base/openssl-1.1.1w/include hb_server.c -L/home/user/work/base/openssl-1.1.1w -lssl -lcrypto -Wl,-rpath,/home/user/work/base/openssl-1.1.1w -o hb_server_base

ビルド例 (BASE): gcc -g -O0 -I/home/user/work/base/openssl-1.1.1w/include hb_server.c -L/home/user/work/base/openssl-1.1.1w -lssl -lcrypto -Wl,-rpath,/home/user/work/base/openssl-1.1.1w -o hb_server_base

### Limitations / notes / 制約・注記

No CVE exists for this issue; the effect per connection is bounded (~170 KiB) and the DoS needs many idle connections, as the OpenSSL blog explains. The PoC measures the server-side effect precisely in-process (mallinfo2) and with the stock s_server under gdb; the glibc fragmentation/RSS-retention aspect described by the reporter was not reproduced. DTLS is not covered by the fix (as upstream).

本件に CVE は無い; 接続あたりの影響は有界 (約 170 KiB) で、OpenSSL ブログの説明どおり DoS には多数の放置接続が必要。PoC はサーバ側の影響をプロセス内 (mallinfo2) と標準 s_server + gdb で正確に計測した; 報告者が述べる glibc の断片化/RSS 高止まりの側面は再現していない。修正は DTLS を対象としない (上流同様)。

