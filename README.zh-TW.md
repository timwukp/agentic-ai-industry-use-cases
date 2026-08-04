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
| `skills/` | AgentCore Skills（git 源；合併後接線） |
| `infra/cdk/` | 11 個 CDK stack：SharedSecurity、Auth、FinanceData、FinanceTools、Api、Web，以及非金融行業各一個 `IndustryStack`（Healthcare、Insurance、Retail、Manufacturing、Realestate） |
| `deploy/` | 編排器 + 冪等腳本（gateway、memory、seed、render、smoke） |
| `web/` | 統一響應式 PWA（Vite + React 19 + Tailwind + Amplify Auth） |
| `tests/` | 單元測試（pytest + moto）、基礎設施（CDK assertions）、E2E（Playwright） |

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
.venv/bin/python deploy/smoke_suite.py      # gateway 工具、知識庫、記憶（JWT 終端用戶路徑）
cd tests/e2e && BASE_URL=https://<cloudfront> E2E_EMAIL=... E2E_PASSWORD=... npx playwright test
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

## 數據誠實原則

行情數據是**確定性模擬**（`tools/shared/toolkit/market_sim.py`）——同一交易日內穩定、
可重現、無需 API key。所有模擬數據都帶有 `"source": "simulated"` 標記，且代理被指示
必須披露。訂單是對演示訂單簿（DynamoDB）的真實寫入，會真正改變持倉。真實世界查詢
（新聞、SEC 文件）通過 harness 內建瀏覽器工具完成。

## 成本

演示規模月成本估算（us-east-1）：CloudFront/S3/Lambda/DynamoDB 按需 ≈ $1–5，
S3 Vectors ≈ 幾美分，Cognito Plus 按 MAU 計費演示規模 ≈ $0，無 NAT/OpenSearch。
主要變量是測試期間的 Bedrock 模型調用。

## 免責聲明

演示/參考架構。金融數據為模擬——不構成投資建議。生產使用前請自行評估安全、
合規與成本。

## 授權

Apache-2.0
