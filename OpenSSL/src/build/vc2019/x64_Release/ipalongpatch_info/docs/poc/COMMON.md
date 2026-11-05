# IPALongPatch PoC / verification — common instructions (共通指示)

(EN) This file is the verbatim text of the common instructions that the orchestrating session gave to the five delegated verification agents (see readme.md, section 8, item 6). The English original is kept unmodified as a record of how the PoC verification was conducted; it uses the absolute paths of the verification environment (/home/user/work/...). A Japanese translation follows the original text.

(JA) 本ファイルは、統括セッションが 5 つの検証エージェントに与えた共通指示の原文である (readme.md の 8 節 6) 参照)。PoC 検証がどのように実施されたかの記録として英語の原文を無修正で保持しており、検証環境の絶対パス (/home/user/work/...) が使われている。原文の後に日本語訳を付す。

---


You are verifying security patches that were back-ported to OpenSSL 1.1.1w
(result: openssl-1.1.1w-ipalongpatch_20261102). For EACH vulnerability assigned to
you, you must show (a) that the UNPATCHED OpenSSL 1.1.1w exhibits the
vulnerability (crash / ASan report / memory growth / wrong behaviour / timing or
structural leak), and (b) that the PATCHED build no longer does, and (c) that the
patched build still behaves correctly for normal (benign) use of the same
feature (no regression).

## Locations (READ ONLY unless stated otherwise)
- Pristine 1.1.1w source tree:            /home/user/work/src_1.1.1w/openssl-1.1.1w
- Patched source tree (git, final):        /home/user/work/patched/openssl-1.1.1w-ipalongpatch_20261102
  (per-CVE patch files: /home/user/work/deliver/ipalongpatch_info/patch_files_for_each_cve/)
- Ubuntu reference patches:                /home/user/work/debian_esm6/debian/patches/ (names CVE-*.patch, lp2161371.patch, openssl-1.1.1-pkcs1-implicit-rejection.patch)
- Research notes about each CVE (Japanese/English, with official advisory quotes):
                                           /home/user/work/research/cve_info.md
- Builds (NEVER run make/Configure/clean in these directories; never edit them):
  * BASE  (unpatched 1.1.1w, debug, in-tree):      /home/user/work/base/openssl-1.1.1w
        libs: libcrypto.so.1.1 libssl.so.1.1 libcrypto.a libssl.a ; app: apps/openssl ; headers: include/
  * BASE-ASAN (unpatched, -fsanitize=address):     /home/user/work/base_asan   (out-of-tree build of the pristine source)
        libs in that dir; generated headers: /home/user/work/base_asan/include ; other headers: /home/user/work/src_1.1.1w/openssl-1.1.1w/include
  * PATCHED (debug):                               /home/user/work/patched/build (out-of-tree build of the patched tree)
        generated headers: /home/user/work/patched/build/include ; other headers: /home/user/work/patched/openssl-1.1.1w-ipalongpatch_20261102/include
  * PATCHED-ASAN:                                  /home/user/work/patched/build-asan
  The ASan builds may still be compiling when you start: wait until the file
  <dir>/build.log ends with "BUILD EXIT: 0" (poll with sleep) before using them.
- Running the command line tool of a build:  <builddir>/util/shlib_wrap.sh <builddir>/apps/openssl <args>
  (shlib_wrap.sh sets LD_LIBRARY_PATH to that build's libraries).
- Compiling your own C PoC against a build (example for PATCHED; swap the paths for the other builds):
    gcc -g -O0 -Wall -I/home/user/work/patched/build/include -I/home/user/work/patched/openssl-1.1.1w-ipalongpatch_20261102/include \
        poc.c -L/home/user/work/patched/build -lssl -lcrypto -Wl,-rpath,/home/user/work/patched/build -o poc_patched
  For the ASan builds add -fsanitize=address (and run with ASAN_OPTIONS=detect_leaks=0 if leak reports get in the way).
  For BASE (in-tree) use -I/home/user/work/base/openssl-1.1.1w/include and -L/home/user/work/base/openssl-1.1.1w.
  Internal (non-exported) functions can be reached by linking the static libraries
  (<builddir>/libcrypto.a <builddir>/libssl.a -ldl -pthread) and including the internal
  headers (<srcdir>/include/crypto/*.h, <srcdir>/crypto/..., <srcdir>/ssl/...).
- gdb and valgrind are installed. Debug builds (-d) have full symbols.

## Your working directory
- Put everything you create under /home/user/work/poc/<NNN>_<CVE>/ (one directory per
  item, NNN = 3-digit patch number given in your task), e.g. the PoC script(s), generated
  test input files (small ones), a `run_poc.sh` that runs the whole demonstration against
  BASE(-ASAN) and PATCHED(-ASAN) and prints a clear verdict, and raw output captures.
- Scripts you write in Python must be run with `python3 -I` ; prefer Python 3 or C.
  Downloaded/extracted files are not involved; everything is local.
- Do not use the network. Do not install packages. Do not touch files outside
  /home/user/work/poc/ and the log directory below. Never modify the source trees or builds.

## Deliverables (per item) — all MUST exist when you finish
1. Log file (the formal evidence record), path:
      /home/user/work/deliver/ipalongpatch_info/logs/<YYYYMMDD_HHMMSS>_<NNN>of033_<CVENUMBER>_<CVEINFO>.log
   where <YYYYMMDD_HHMMSS> is the JST time at which you START the verification of that
   item (JST = UTC+9; use `TZ=Asia/Tokyo date +%Y%m%d_%H%M%S`), and <CVENUMBER>, <CVEINFO>
   are given in your task table (copy them exactly).
   Encoding: UTF-8 WITH BOM (write the 3 bytes EF BB BF first), LF line endings.
   Contents, in this order:
     a. the environment block: copy /home/user/work/poc/ENV_HEADER.txt verbatim;
     b. "Verification start: YYYY/MM/DD HH:MM:SS (JST)";
     c. a description of the vulnerability and of the PoC strategy — English paragraph
        first, then the same content in Japanese (英語の段落の直後に同内容の日本語段落);
        keep alternating EN -> JA at paragraph granularity for all narrative text;
     d. the exact commands executed and their raw stdout/stderr (truncate very large
        outputs to the relevant parts, but keep all crash/ASan/gdb evidence);
     e. the gdb / ASan / valgrind evidence for the unpatched build (backtrace, report);
     f. the output for the patched build showing the issue no longer occurs;
     g. the regression / side-effect check (benign use still works) and its output;
     h. "Verification end: YYYY/MM/DD HH:MM:SS (JST)", "Duration: HH:MM:SS";
     i. "Verdict: PASS" (or FAIL, with honest explanation) — EN and JA.
   If an initial attempt failed and you had to fix the PoC or re-test, keep that history
   in the log (the record of trial and error is wanted).
2. Report fragment (Markdown, UTF-8, bilingual EN then JA per paragraph):
      /home/user/work/poc/results/<NNN>_report.md
   Sections: "Vulnerability mechanism (as observed in the code)", "PoC design",
   "Observed behaviour BEFORE the patch (evidence excerpts)", "Observed behaviour AFTER
   the patch", "Regression check", "How to reproduce manually (step-by-step commands a
   human can run)", "Limitations / notes". Reference the log file name.
3. Result record (JSON):  /home/user/work/poc/results/<NNN>.json with keys:
      nnn, cve, cveinfo, log_file, start_jst, end_jst, duration, verdict,
      before_en, before_ja, after_en, after_ja, method_en, method_ja,
      regression_en, regression_ja, tools (list), poc_files (list), limitations_en, limitations_ja
4. Final answer to the orchestrator: a SHORT Japanese summary per item (verdict, one
   sentence of evidence, anything that could not be demonstrated and why). Do not paste
   the logs into the answer.

## Quality rules
- Be rigorous and honest. A PoC that does not actually demonstrate the issue must be
  reported as such (verdict FAIL or PARTIAL with the reason); never fabricate output.
- Prefer deterministic crash/ASan/gdb evidence. For timing side channels, combine a
  structural demonstration (e.g. gdb showing data-dependent BIGNUM tops or the variable-time
  function being called) with a statistical timing measurement where feasible; state the
  statistical confidence honestly (this is a shared 4-vCPU VM; other builds may be running).
- Each PoC must be run against BOTH an unpatched build and a patched build. Use the ASan
  builds for memory-safety issues (they make OOB/UAF evident) and the debug builds for gdb.
- Also check for memory leaks / sanity of the patched code path with valgrind
  (--leak-check=full, non-ASan builds) or ASan leak detection where practical.
- Keep CPU usage reasonable: do not run more than 2 heavy processes at once.
- Timestamps are JST and must say "(JST)".
- Use the Ubuntu patch and the IPALongPatch patch file of the item to understand the exact
  code change; the research notes give the official advisory text for the mechanism.

---

# 日本語訳 (Japanese translation of the instructions above)

あなたは、OpenSSL 1.1.1w にバックポートしたセキュリティパッチ (成果物: openssl-1.1.1w-ipalongpatch_20261102) を検証する。担当する各脆弱性について、(a) 未パッチの OpenSSL 1.1.1w が脆弱性を示すこと (クラッシュ / ASan 報告 / メモリ増大 / 誤動作 / タイミングまたは構造的な漏えい)、(b) パッチ済みビルドではそれが起きないこと、(c) パッチ済みビルドが同じ機能の正常な (無害な) 利用に対して引き続き正しく動作すること (回帰なし) を示さなければならない。

## 配置 (特記なき限り読み取り専用)
- 素の 1.1.1w ソースツリー: /home/user/work/src_1.1.1w/openssl-1.1.1w
- パッチ済みソースツリー (git、最終): /home/user/work/patched/openssl-1.1.1w-ipalongpatch_20261102 (CVE 別パッチファイル: /home/user/work/deliver/ipalongpatch_info/patch_files_for_each_cve/)
- Ubuntu 参照パッチ: /home/user/work/debian_esm6/debian/patches/ (名称 CVE-*.patch、lp2161371.patch、openssl-1.1.1-pkcs1-implicit-rejection.patch)
- 各 CVE の研究ノート (日英、公式アドバイザリの引用付き): /home/user/work/research/cve_info.md
- ビルド (これらのディレクトリで make/Configure/clean を実行してはならず、編集もしてはならない):
  * BASE (未パッチ 1.1.1w、デバッグ、ツリー内ビルド): /home/user/work/base/openssl-1.1.1w — ライブラリ libcrypto.so.1.1 libssl.so.1.1 libcrypto.a libssl.a; アプリ apps/openssl; ヘッダ include/
  * BASE-ASAN (未パッチ、-fsanitize=address): /home/user/work/base_asan (素のソースのツリー外ビルド) — 生成ヘッダ /home/user/work/base_asan/include、その他のヘッダ /home/user/work/src_1.1.1w/openssl-1.1.1w/include
  * PATCHED (デバッグ): /home/user/work/patched/build (パッチ済みツリーのツリー外ビルド) — 生成ヘッダ /home/user/work/patched/build/include、その他のヘッダ /home/user/work/patched/openssl-1.1.1w-ipalongpatch_20261102/include
  * PATCHED-ASAN: /home/user/work/patched/build-asan
  ASan ビルドは開始時点でまだコンパイル中のことがある: <dir>/build.log が "BUILD EXIT: 0" で終わるまで (sleep で監視して) 待ってから使うこと。
- ビルドのコマンドラインツールの実行: <builddir>/util/shlib_wrap.sh <builddir>/apps/openssl <args> (shlib_wrap.sh がそのビルドのライブラリへ LD_LIBRARY_PATH を設定する)。
- 自作 C PoC をビルドに対してコンパイルする例 (PATCHED の場合; 他のビルドではパスを置き換える):
    gcc -g -O0 -Wall -I/home/user/work/patched/build/include -I/home/user/work/patched/openssl-1.1.1w-ipalongpatch_20261102/include poc.c -L/home/user/work/patched/build -lssl -lcrypto -Wl,-rpath,/home/user/work/patched/build -o poc_patched
  ASan ビルドでは -fsanitize=address を追加する (リーク報告が邪魔なら ASAN_OPTIONS=detect_leaks=0 で実行)。BASE (ツリー内) では -I/home/user/work/base/openssl-1.1.1w/include と -L/home/user/work/base/openssl-1.1.1w を使う。内部 (非公開) 関数には静的ライブラリ (<builddir>/libcrypto.a <builddir>/libssl.a -ldl -pthread) をリンクし内部ヘッダ (<srcdir>/include/crypto/*.h、<srcdir>/crypto/...、<srcdir>/ssl/...) をインクルードすれば到達できる。
- gdb と valgrind がインストール済み。デバッグビルド (-d) は完全なシンボルを持つ。

## 作業ディレクトリ
- 作成するものはすべて /home/user/work/poc/<NNN>_<CVE>/ (項目ごとに 1 ディレクトリ、NNN = タスクで与えた 3 桁のパッチ番号) に置く。例: PoC スクリプト、生成したテスト入力 (小さいもの)、BASE(-ASAN) と PATCHED(-ASAN) に対して実証全体を実行し明確な判定を表示する run_poc.sh、生の出力の記録。
- Python で書くスクリプトは python3 -I で実行する。Python 3 または C を推奨。ダウンロード/展開ファイルは関与せず、すべてローカルである。
- ネットワークを使わない。パッケージをインストールしない。/home/user/work/poc/ と下記のログディレクトリ以外のファイルに触れない。ソースツリーとビルドを決して変更しない。

## 成果物 (項目ごと) — 完了時にすべて存在しなければならない
1. ログファイル (正式な証拠記録)、パス: /home/user/work/deliver/ipalongpatch_info/logs/<YYYYMMDD_HHMMSS>_<NNN>of033_<CVENUMBER>_<CVEINFO>.log。<YYYYMMDD_HHMMSS> はその項目の検証を開始した JST 時刻 (JST = UTC+9; `TZ=Asia/Tokyo date +%Y%m%d_%H%M%S` を使う)、<CVENUMBER>、<CVEINFO> はタスクの表で与えたもの (そのまま複写)。文字コード: BOM 付き UTF-8 (先頭に 3 バイト EF BB BF)、改行 LF。内容の順序: a. 環境ブロック (/home/user/work/poc/ENV_HEADER.txt をそのまま複写); b. "Verification start: YYYY/MM/DD HH:MM:SS (JST)"; c. 脆弱性と PoC 方針の説明 — 英語の段落の直後に同内容の日本語段落を置き、以降の説明文も段落単位で英→日を交互に; d. 実行した正確なコマンドと生の stdout/stderr (非常に大きい出力は該当部分へ要約してよいが、クラッシュ/ASan/gdb の証拠はすべて残す); e. 未パッチビルドの gdb / ASan / valgrind の証拠 (バックトレース、報告); f. パッチ済みビルドで問題が起きないことを示す出力; g. 回帰・副作用確認 (正常利用が動作すること) とその出力; h. "Verification end: YYYY/MM/DD HH:MM:SS (JST)"、"Duration: HH:MM:SS"; i. "Verdict: PASS" (または FAIL と正直な説明) — 英日。初回の試行が失敗して PoC の修正や再試験をした場合、その経過をログに残す (試行錯誤の記録を求めている)。
2. レポート断片 (Markdown、UTF-8、段落ごとに英→日): /home/user/work/poc/results/<NNN>_report.md。節: "Vulnerability mechanism (as observed in the code)"、"PoC design"、"Observed behaviour BEFORE the patch (evidence excerpts)"、"Observed behaviour AFTER the patch"、"Regression check"、"How to reproduce manually (step-by-step commands a human can run)"、"Limitations / notes"。ログファイル名を参照すること。
3. 結果記録 (JSON): /home/user/work/poc/results/<NNN>.json。キー: nnn, cve, cveinfo, log_file, start_jst, end_jst, duration, verdict, before_en, before_ja, after_en, after_ja, method_en, method_ja, regression_en, regression_ja, tools (リスト), poc_files (リスト), limitations_en, limitations_ja。
4. 統括者への最終回答: 項目ごとの短い日本語の要約 (判定、証拠の一文、実証できなかったことがあればその理由)。ログを回答に貼り付けない。

## 品質ルール
- 厳密かつ正直であること。問題を実際に実証できていない PoC はそのように報告する (理由付きで FAIL または PARTIAL)。出力を決して捏造しない。
- 決定的なクラッシュ/ASan/gdb の証拠を優先する。タイミングサイドチャネルでは、構造的な実証 (例: データ依存の BIGNUM top や可変時間関数が呼ばれることを gdb で示す) と、可能であれば統計的なタイミング計測を組み合わせ、統計的な確からしさを正直に述べる (共有の 4 vCPU VM であり、他のビルドが同時に走っている可能性がある)。
- 各 PoC は未パッチビルドとパッチ済みビルドの両方に対して実行する。メモリ安全性の問題には ASan ビルド (OOB/UAF が明確になる) を、gdb にはデバッグビルドを使う。
- パッチ済みコード経路のメモリリークや健全性も valgrind (--leak-check=full、非 ASan ビルド) または実用的なら ASan のリーク検出で確認する。
- CPU 使用を適度に保つ: 重いプロセスを同時に 3 つ以上走らせない。
- 時刻は JST とし、必ず "(JST)" と記す。
- 各項目の Ubuntu パッチと IPALongPatch パッチファイルを使って正確なコード変更を理解すること。研究ノートにはメカニズムに関する公式アドバイザリの原文がある。
