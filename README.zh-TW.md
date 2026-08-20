# 行業 Agentic AI 應用案例 — 基於 AWS Bedrock AgentCore Harness

[English](README.md)

以 **AWS Bedrock AgentCore Harness** 重建的行業 Agentic AI 應用——聲明式全託管代理
（無需容器、無需自寫 agent loop），配備 **Gateway MCP 工具**、**Bedrock 知識庫
（S3 Vectors）**、**託管記憶（Memory）**，以及單一 **Cognito 保護的響應式 PWA** 前端。

**六個行業全部已端到端部署並驗證**——每個行業都有自己的 harness、帶 5 個 MCP 工具 target
的 Gateway、S3 Vectors 知識庫、託管記憶，以及日誌/追蹤投遞，全部可從同一個 PWA 訪問。
六個行業也都有專門設計的 dashboard，各由自己的 REST 路由（每行業 3-5 條）支撐，已對照
已部署的 API 驗證，並在桌面與行動裝置兩種寬度下截圖檢查。

## 架構

![架構圖](docs/architecture.svg)

### 請求流

![請求流](docs/request-flow.svg)

**安全設計：** Cognito 用戶池（TOTP MFA、進階安全、12 字符密碼），每個入口都驗證
JWT（harness `customJWTAuthorizer` + API Gateway authorizer），WAF 實際掛載到
CloudFront，Lambda 最小權限 IAM，數據存儲 KMS 加密，私有 S3 + CloudFront OAC，
代碼中無長期憑證。

## 倉庫結構

| 路徑 | 說明 |
|---|---|
| `harnesses/<industry>/` | 聲明式 harness 配置模板、記憶策略、系統提示詞 |
| `tools/<industry>/` | Gateway Lambda 工具處理器 + MCP 工具 schema |
| `tools/shared/toolkit/` | 共享 dispatch、DynamoDB 輔助、確定性行情模擬器 |
| `kb/<industry>/seed-docs/` | 知識庫種子文檔（政策、產品指南） |
| `skills/` | AgentCore Skills（git 源讀 main；`theory-to-production` 由自主理論偵察 agent 實時載入） |
| `infra/cdk/` | 11 個 CDK stack：SharedSecurity、Auth、FinanceData、FinanceTools、Api、Web，以及非金融行業各一個 `IndustryStack`（Healthcare、Insurance、Retail、Manufacturing、Realestate） |
| `deploy/` | 編排器 + 冪等腳本（gateway、memory、seed、render、smoke）；`deploy/theory-scout/` 為月度研究偵察驅動器 + 排程（[文檔](deploy/theory-scout/README.md)） |
| `web/` | 統一響應式 PWA（Vite + React 19 + Tailwind + Amplify Auth） |
| `tests/` | 單元測試（pytest + moto）、基礎設施（CDK assertions）、E2E（Playwright） |
| `research/` | 預註冊驗證研究 + 10 個預註冊方法測試（10–50 年真實數據）：凍結協議、自校準儀器、結果與判定（[記分板](research/findings_addendum.md)） |

## 部署

前置：Python 3.11+、Node 22+、AWS 憑證、`boto3 >= 1.43.51`。

```bash
make setup            # venv + 依賴 + CDK CLI
make test             # 單元 + 基礎設施測試
make deploy-finance   # CDK → 種子數據 → gateway → harness → memory → 可觀測性 → 冒煙
make deploy-web       # 構建 PWA → 部署 WebStack → 發佈到 CloudFront

# 其他行業，同一條流水線：
python deploy/deploy.py --industry healthcare|insurance|retail|manufacturing|realestate
```

`deploy/deploy.py` 按序執行所有步驟且冪等——可安全重跑，或用 `--from-step gateway` /
`--only smoke` 斷點續跑。每個行業的 CDK 輸出會**合併**進 `deploy/outputs/cdk-outputs.json`
而非覆蓋，所以部署第 N 個行業不會弄壞前面 N-1 個。底層使用 AgentCore Harness Builder
skill 的腳本（preflight、validate、create/update harness、invoke）；skill 位置不同時設置
`HARNESS_SKILL_DIR`。

### 驗證

```bash
make test                                   # 單元（pytest + moto）+ 基礎設施 + 前端（node --test）
.venv/bin/python deploy/smoke_suite.py      # gateway 工具、知識庫、記憶（JWT 終端用戶路徑）
make verify-harnesses                       # 驗證每個「線上」harness 真的能呼叫到它的工具
cd tests/e2e && BASE_URL=https://<cloudfront> E2E_EMAIL=... E2E_PASSWORD=... npx playwright test
```

`make verify-harnesses` 之所以存在，是因為一次其他檢查全都沒抓到的故障。線上 harness 的
`allowedTools` 漂移成了一組**匹配不到任何工具**的 pattern，導致每個 agent 只看得到自己的
`skills` 工具——而它不是報錯拒答，是憑記憶回答並**編造行情數據**（工具回傳 S&P 500 為 6,120.35，
它報 5,248）。當時 gateway 是 `READY`、所有 target 是 `READY`、17 個工具用 MCP 直接呼叫全部正常、
IAM 模擬結果是 `allowed`、每個部署步驟 exit code 都是 0。唯一線索是藏在 tool-result 事件裡的
`"Unknown tool: …"`，而 smoke 腳本和前端都把那個事件丟掉了。所以這個檢查是要求線上 harness
**實際使用**一個工具，然後讀 **tool-result 事件而不是讀文字**——一個連不到工具的 agent 會產出
看起來很有信心的文字，所以拿文字內容做斷言比不檢查更糟。

### 可觀測性與線上評估

每個 harness 會把 OTel span 送到 X-Ray Transaction Search（`aws/spans` log group），每個行業
配有一個線上評估器（`<industry>_harness_quality`）定期對這些 span 打分；結果落在
`/aws/bedrock-agentcore/evaluations/results/…`，也可在 AgentCore 控制台的 **Evaluations**
頁面查看。

這條管線有自己的靜默故障模式，而我們親身踩到了：harness role 缺少
`xray:PutTraceSegments` / `xray:PutTelemetryRecords` / `cloudwatch:PutMetricData`，導致
runtime 的 OTel exporter 每一批 span 都被 403 拒絕。沒有任何地方浮現這個錯誤——harness
回應一切正常、log delivery 顯示 `ENABLED`、評估器顯示 `ACTIVE`——但 `aws/spans` 從未收到
span，評估器無料可評，結果 log group 空了六個月。現在 `IndustryStack` 的 harness role 帶有
`ObservabilityTraces` statement（resource 為 `*`，因為 `xray:Put*` 不支持資源級限定）。
要確認管線活著，請驗證 span 有到達，而不是看各組件自報健康：

```bash
aws logs filter-log-events --log-group-name aws/spans \
  --filter-pattern '"harness_finance_trading"' --max-items 1   # 任一次對話後應 ≥1 筆
```

## 六個行業

每個行業都是同一種結構：4 個領域工具 Lambda + 1 個知識庫搜索 Lambda，掛在各自的 Gateway
（5 個 MCP target）後面，配一個 harness、一個知識庫、一個 Memory。

| 行業 | 代理 | Gateway 工具 target | 前端 |
|---|---|---|---|
| 金融交易 | `finance_trading_assistant` | market-data / portfolio / risk / trading / kb | Dashboard + 聊天 |
| 醫療健康 | `healthcare_medical_assistant` | clinical / analytics / records / scheduling / kb | Patient 360 dashboard + 聊天 |
| 保險理賠 | `insurance_claims_assistant` | claims / fraud-detection / policy / settlement / kb | 理賠隊列 dashboard + 聊天 |
| 零售庫存 | `retail_inventory_assistant` | inventory / demand-forecast / supplier / pricing / kb | 庫存 dashboard + 聊天 |
| 製造維護 | `manufacturing_maintenance_assistant` | equipment / prediction / maintenance / parts / kb | 設備健康 dashboard + 聊天 |
| 房地產估值 | `real_estate_valuation_assistant` | valuation / market / investment / property / kb | 估值 dashboard + 聊天 |

六個行業的業務決策流程——逐階段的關卡、閾值與人工審批點，從業者視角撰寫——記錄在 [docs/business-flows.zh-TW.md](docs/business-flows.zh-TW.md)。

六個行業都是同一條命令上線的——`python deploy/deploy.py --industry <name>`——且**每個行業
零新增 stack 代碼**：參數化的 `IndustryStack` 加上 gateway/harness/memory/observability
腳本，全部從 `deploy/industries.py` 讀取配置。每個 dashboard 的 REST 路由宣告在
`DASHBOARD_ROUTES`（`infra/cdk/app.py`），由每行業一個 `dashboard_api` Lambda 提供服務，
而它 import 的正是 agent 透過 Gateway 呼叫的**同一批**工具處理器——所以瓷磚上的數字與
agent 在聊天中引用的數字出自同一個函數，而非兩套實作。

### Dashboard 數據一致性

模擬數據的建構方式保證：描述同一個實體的數字不可能互相矛盾。每個衍生數字都由它上方顯示的
數字計算而來，且觸及同一實體的每條路由都讀取同一個共享基準（`tools/shared/toolkit/` 中的
`property_basis`、`asset_basis`、`retail_basis`、`market_basis`）。各自獨立抽樣會產生一眼
可見的荒謬結果——例如市場瓷磚寫著 `$528K`，而它自己下方的歷史圖表最高點卻是 `$780K`；
標為 `Median $/Sq Ft`（每平方英尺中位數）的瓷磚顯示的數字，在其下方表格的任何一列都找不到；
或是 `YoY +8.8%`（年同比）瓷磚上方的圖表標題，對同樣的十二個月寫著 `+8.1% over period`。
`tests/unit/test_industry_dashboard_apis.py` 為上述每一項都建立了回歸測試。

### 引導式起始問題（Starter Questions）

每個行業的 AI Assistant 對話面板在空白狀態下會列出 3–5 個起始問題
（`web/src/industries/starterPrompts.ts`），讓初次訪問者一進來就有地方可點。措辭模擬該職位
真實從業者的問法，並把唯讀查詢排在前面，確保第一次點擊不會改動任何狀態；點擊後**直接送出**
（不同於 dashboard 的 **Ask agent** 按鈕——那些是預填，因為它們是在對話進行中才觸發的）。

問題文字裡的每個實體 ID 與 enum 值都對應真實工具資料。這件事比聽起來重要：共享基準
（basis）遇到不存在的 ID 是**編造**而非報錯，所以 `sku_basis("SKU-1001")` 會回傳一個看似
合理的「Product 1001」，而 agent 會理直氣壯地回答一個在 app 其他地方根本不存在的商品。
`tests/unit/test_starter_prompts.py` 直接解析 TypeScript 原始檔（而非複製一份問題清單——
複製必然會漂移），逐一斷言所有 SKU、設備資產、醫師、病人、市場郵遞區號與股票代號都存在於
共享目錄中，每個明示的 enum 值都在處理器自己接受的集合內，並實際呼叫全部 26 條工具路徑
確認都回傳有內容的資料。

### 答案的可讀性

「答案變成一大團看不懂的文字」這個問題分三層修。

**Markdown 渲染。** 助手回覆以 GitHub-flavored Markdown 解析
（`web/src/components/Markdown.tsx`）。在此之前回覆是走 `whitespace-pre-wrap`，所以模型
其實一直都在輸出正確的表格，只是被渲染成一堆生的 `|` 符號——這是渲染 bug，不是 prompt 問題。
每個元素都明確指定樣式而非套用 typography plugin，因為那些預設值假設的是淺色背景、全寬文章；
表格加上水平滾動條，因為六欄數字在手機上放不下，而靜默裁切會吃掉最後一欄——通常正是被問到的那一欄。

**臨時圖表面板。** 當答案建立在某個值得繪圖的工具輸出上時，圖表會出現在行業 dashboard 上方
（`web/src/components/AnswerChartPanel.tsx`）；在 `lg` 以下則改為內嵌在該則訊息底下。它是
**疊在 dashboard 上層而非取代它**，且可關閉——dashboard 是常駐視圖，這個面板只是某一個問題的副產品。

圖表資料來自**agent 自己收到的那份工具輸出**，從 invoke 事件流中擷取
（`web/src/lib/toolTrace.ts`）。這裡刻意**不**去重新呼叫對應的 dashboard REST 路由：重新呼叫
可能回傳與畫面上那段答案不同的數字（參數不同、時間戳較晚），而一張與旁邊文字**默默不一致**的
圖表，比沒有圖表更糟。46 個識別器（`web/src/lib/chartSpec.ts`）——覆蓋到每個行業的每一個預設
問題都會出面板（26/26，由 `tests/e2e/starter-charts-audit.spec.ts` 對線上環境實測）——各自重新
驗證它預期的資料形狀，不符就回傳空值，所以無法識別的工具是**不出面板**，而不是猜一個出來。
閾值虛線另外遵守兩條規則：落在軸範圍外、會被 recharts 默默丟棄的線改為撐開軸
（`ifOverflow="extendDomain"`）；而一條遠到會把數據本身壓縮到不足三分之一畫面的線，識別器會
主動不畫——唯一例外是感測器圖表最近的那條限值線，因為讀數與限值之間的距離**就是答案本身**。

事件對應關係是最不直觀的部分：`toolResult` 事件既不帶工具名稱也不帶 `toolUseId`，名稱只能透過
`contentBlockIndex` → `toolUseId` → `name` 反查，而 block index 在**同一輪對話內會被重複使用**
——失效模式就是把 A 工具的資料掛在 B 工具的名字底下。失敗的呼叫、非 JSON 的回應內容、以及查不到
名稱的結果，全部拒絕：閘道故障期間 agent 曾寫出一段語氣自信但指數數字全是編造的行情摘要，若當時
把「嘗試過的呼叫」也畫成圖，就會是一張空圖表配一段虛構文字。

**UI 語言。** 介面支援 16 種語言自選（英文、繁體中文、簡體中文、日文、韓文、法文、西班牙文、
義大利文、葡萄牙文、德文、印尼文、馬來文、泰文、越南文、菲律賓文、印地文），選擇器在頁首和登入頁。
i18n 層為手寫（`web/src/i18n/`）：每個語言一個 TypeScript 目錄檔，以 `satisfies Messages` 對齊英文
schema，任何語言漏譯一個 key 都是編譯錯誤；英文打包在主 bundle 作為兜底，其餘 15 種按需載入各自的
chunk（gzip 後各約 10 kB）。圖表標題只在渲染期翻譯——spec 的英文字串仍是它的 identity（去重、分頁、
E2E hook），由一個重建測試釘死：從目錄 key 加參數必須精確重建出每一條英文原串
（`tests/unit/chartI18n.test.ts`）。payload 值（id、enum、後端文字）刻意原樣穿過不翻譯。

**回覆語言。** Agent 用提問的語言回答，文字判斷不了時由 UI 語言補位
（`web/src/lib/replyLanguage.ts`）。兩級訊號：打字內容的確定性非拉丁文字直接勝出（假名→日文、
諺文→韓文、泰文、天城文→印地文；漢字用選擇器做繁簡裁決），而拉丁文字——單憑字集無法斷定是哪種
語言——跟隨選擇器，所以在泰文 UI 下點英文預設問題會得到泰文回答。夾滿英文股票代號的技術中文仍判為
中文，英文句子裡混進一個中文字仍判為英文；在未動過的英文默認下，真正無法判斷時仍完全不下指令，
因為下錯指令比不下指令更糟。

## 數據誠實原則

金融行業現在有**兩個明確分離的數據世界**，每筆數據都標明自己屬於哪一個：

- **`"source": "live"`** —— 真實美國市場數據（追蹤股票報價、指數行情走 QQQ/SPY ETF 代理
  ——Twelve Data 免費層不含真指數符號，故用 ETF 代理並標記 `proxy: true`；Nasdaq 綜合指數
  官方日線收盤來自 FRED `NASDAQCOM`——完整國債殖利率曲線、政策利率、基本面），僅來自
  官方數據源：**Finnhub**、**Twelve Data**（黃金，Phase 2 用）、**FRED**（聖路易斯聯儲）。唯一調用外部 API 的組件是排程採集 Lambda（EventBridge
  Scheduler，`America/New_York` 時區的交易時段）；工具和儀表板都只讀它寫入的 DynamoDB
  快照，所以磁貼上的數字和代理引用的數字來自同一行。Live 數據帶 `provider`、
  `fetched_at`、`delay`，UI 以綠色 **LIVE** 徽章呈現；快照超過採集週期 2 倍即標記
  `"stale": true`。歷史數據落入 S3（`market/<dataset>/dt=…/*.jsonl.gz`，可用 Athena 查詢）。
  我們刻意**拒絕了爬蟲方案**（例如用瀏覽器工具抓 bloomberg.com）：違反網站服務條款、
  DOM 一改版就斷、抓到的數字沒有任何新鮮度契約。
- **`"source": "simulated"`** —— 演示交易系統（`tools/shared/toolkit/market_sim.py`）：
  確定性、可重現、無需 API key。投組、訂單、風險和模擬行情區塊留在這個世界，成交價
  與 P&L 保持內部一致（琥珀色徽章）。訂單是對演示訂單簿（DynamoDB）的真實寫入，會
  真正改變持倉。

代理的系統提示要求：呈現 live 數字必須披露數據源與時點；答案若混合 live 市場背景與
模擬投組狀態，必須明說。真實世界查詢（新聞、SEC 文件）通過 harness 內建瀏覽器工具完成。

在 live/simulated 之外還有兩個數據來源類別：

- **`"source": "derived"`**（紫色徽章）—— 每晚由 Haiku 從新聞標題（Finnhub + GDELT）
  打分出的 13 因子地緣政治載荷。永遠標 `grade: "hypothesis"`：未經驗證的信號，
  用於刻畫「世界正在擔心什麼」。
- **`"source": "model"`**（天藍徽章）—— **PRISM**（*Probabilistic Regime & Impact
  Shock Model*，概率體制與衝擊影響模型）的輸出：夜間容器 Lambda 批次，基於回填的
  10 年以上官方數據擬合——高斯 HMM 市場體制；傳遞熵 + Granger 因果掃描（Benjamini-
  Hochberg FDR 校正）；貝葉斯局部投影影響函數（含可信帶）；EVT（GPD 超閾值法）尾部
  風險——校準過的頭條 99% VaR 採用波動率過濾（McNeil-Frey）方法。一條規律只有同時
  通過 FDR 校正**和** walk-forward 樣本外驗證（對照 AR(1)/隨機遊走基準）才標
  **CONFIRMED**，其餘一律 **HYPOTHESIS**。第一條 CONFIRMED 規律——VIX→10 年期美債的
  避險資金流（1/5/20 天視界，q=0.0018）——是在一次預註冊的功效審計更換了因果掃描的
  合併規則之後才浮現的；CONFIRMED 列表短或空就如實顯示——誠實的空列表勝過粉飾的
  列表。quant 批次是本 repo 對 zip-only Lambda 打包規則的唯一受批例外
  （numpy/scipy/statsmodels/hmmlearn 需要容器鏡像）。

### 預註冊驗證研究（`research/`）

PRISM 的聲稱不靠信任，靠檢驗。一項期刊級驗證研究用 10/20/30/40/50 年真實數據對每一層
做了背靠背回測（協議在任何測試代碼之前凍結並打 git tag；全程 point-in-time 紀律——在
t 日只用 ≤t 的數據）：體制層作為歷史透鏡成立（對照 NBER 衰退 + 已知崩盤，AUROC
0.84–0.86），但實時檢測滯後超過 10 個交易日，所以代理將其呈現為背景而非預警；頭條
VaR 校準全綠（Kupiec/Christoffersen）；崩盤「擇時」類問題以脆弱度-對-觸發器框架回答，
因為沒有任何經濟可預測性通過 Hansen SPA 檢驗（見
[research/report.md](research/report.md)、[research/findings.md](research/findings.md)）。

同一套紀律隨後為兩次深度調研（前沿數學 + 經典應用數學）的每個候選方法把關：每個候選
都有凍結協議、數值判定門檻、自校準儀器（植入真值的合成測試）和機械化判定。
**記分板：10 個預註冊測試，2 晉升 / 8 快速失敗**——失敗與晉升以同樣的嚴謹記錄在
[research/findings_addendum.md](research/findings_addendum.md)，因為沒有記錄的失敗一定會
被重複。僅因系統當前表示規模太小而失敗的方法（如 p=5 下的協方差收縮）帶著重啟條件
歸檔於 [research/conditional_candidates.md](research/conditional_candidates.md)。

### 自主理論偵察（`deploy/theory-scout/` + `skills/theory-to-production/`）

上述研究管線不再依賴人記得去跑。一個排程化的 **AgentCore Harness**（*PRISM Theory
Scout*）每月（1 日 02:00 UTC）執行
[theory-to-production skill](skills/theory-to-production/SKILL.md) 的 Phase 0–2：先讀
main 上的記分板與條件候選清單，再以 PRISM **當前**約束指紋為準調研新數學理論，每次
最多一個候選——起草協議並在**花任何真實數據成本之前**，用合成模擬跑完預註冊的正控制
功效檢查。

人機環的關卡就是 PR 本身：scout 的授權硬性止步於分支上的 `DRAFT_protocol_*.md`（不打
tag、不合併、不碰生產路徑）；人來審查、凍結+打 tag、安排真實數據測試。找不到值得起草
的候選就**不開 PR**——誠實空手的週期是有效結果，不是故障。首次完整驗證週期
（2026-08-11）恰好演示了這一點：scout 找到文獻明星候選（Smooth Local Projections，
*ReStat* 2019）且缺陷精確匹配，然後被它自己的功效檢查否決（最佳 28.7% vs 80% 門檻）——
零分支、零 commit，還給人送上一條生產代碼校準線索。交付鏈：EventBridge Scheduler →
CodeBuild（源 = 本 repo main，跑的永遠是審過的驅動器）→ `InvokeHarness`。

### Live 行情初始設置（一次性）

採集器需要 3 個免費 API key 存入 SSM（`secrets` 部署步驟會檢查，缺失時打印以下命令）：

```bash
aws ssm put-parameter --name /agentic/finance/finnhub-api-key    --type SecureString --value '<key>'
aws ssm put-parameter --name /agentic/finance/twelvedata-api-key --type SecureString --value '<key>'
aws ssm put-parameter --name /agentic/finance/fred-api-key       --type SecureString --value '<key>'
```

註冊：[Finnhub](https://finnhub.io/register) · [Twelve Data](https://twelvedata.com/register)
· [FRED](https://fredaccount.stlouisfed.org/apikeys)。免費額度綽綽有餘：排程用量 <2% 的
Finnhub 配額、約 10% 的 Twelve Data 日配額；FRED 無限制。

## 成本

演示規模月成本估算（us-east-1）：CloudFront/S3/Lambda/DynamoDB 按需 ≈ $1–5，
S3 Vectors ≈ 幾美分，Cognito Plus 按 MAU 計費演示規模 ≈ $0，無 NAT/OpenSearch。
主要變量是測試期間的 Bedrock 模型調用。

## 免責聲明

演示/參考架構。金融數據為模擬——不構成投資建議。生產使用前請自行評估安全、
合規與成本。

## 授權

Apache-2.0
