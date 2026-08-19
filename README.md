# 🌊 星海 Web 安全 (StarSea Web Security)

基于 Security.X 威胁情报的浏览器安全防护扩展，支持 Chrome / Edge / 其他 Chromium 内核浏览器。

## 核心功能

- **实时威胁拦截**：基于 4000+ 恶意域名、IP、URL 的本地规则库，毫秒级 O(1) 匹配
- **钓鱼网站识别**：内置假冒软件下载站（图吧工具箱、Fan Control、哔哩哔哩等）特征
- **C2 通信阻断**：拦截已知银狐/ValleyRAT 等僵尸网络 C2 服务器连接
- **恶意下载拦截**：阻止来自已知恶意源的文件下载
- **ML 启发式检测 v5.3**：DGA 域名、Punycode 同形异义字攻击、Typosquatting 编辑距离、云盘滥用、n-gram 分布异常、可疑 TLD 检测
- **白名单系统**：内置可信域 + 用户自定义 + 通配符 + 临时会话放行，优先于所有检测
- **自定义规则**：用户可手动添加域名/IP/URL 黑名单
- **拦截统计**：记录所有拦截事件，按威胁家族和严重程度分类
- **云端威胁情报**：可选配 Security.X 云端 Worker API，支持 VirusTotal 关联查询

## 安装方法

1. 打开 Chrome，地址栏输入 `chrome://extensions/`
2. 右上角开启「开发者模式」
3. 点击「加载已解压的扩展程序」
4. 选择 `starsea-web-security` 文件夹
5. 扩展图标出现在工具栏，安装完成

> Edge 浏览器访问 `edge://extensions/`，同样开启开发者模式后加载。

## 文件结构

```
starsea-web-security/
├── manifest.json          # MV3 扩展配置
├── background.js          # 后台 Service Worker（核心拦截逻辑）
├── lib/
│   ├── matcher.js         # IOC 高性能匹配引擎（Map-based O(1) 查找）
│   ├── ml-engine.js       # ML 推理引擎 v5.3（特征提取 + 加权累积 + 多因子门控）
│   ├── allowlist.js       # 白名单管理器（内置+用户+通配符+会话）
│   └── cloud-client.js    # 云端查杀客户端（Worker API 通信）
├── popup/
│   ├── popup.html         # 弹出面板 UI
│   └── popup.js           # 弹出面板逻辑
├── options/
│   ├── options.html       # 设置页
│   └── options.js         # 设置页逻辑
├── blockpage/
│   └── blockpage.html     # 威胁拦截页（含二次确认 + 加入白名单）
├── rules/
│   └── blocklist.json     # 内置 IOC 规则库（4138条）
└── icons/
    ├── icon16.png
    ├── icon32.png
    ├── icon48.png
    └── icon128.png
```

## 检测流程

```
URL 请求
  → 白名单检查（内置可信域 → 用户自定义 → 通配符 → 临时会话）
  → 精确域名匹配（O(1) Map 查找）
  → 子域名遍历（父域匹配）
  → IP 地址匹配
  → URL 前缀/包含匹配
  → ML 引擎推理（特征提取 → 加权累积打分 → 多因子门控判定）
  → 云端查杀（可选，Security.X Worker API）
  → 拦截/放行
```

### ML 引擎判定逻辑

| 信号类型 | 示例 | 判定方式 |
|---------|------|---------|
| 强信号 | C2 端口、Punycode 攻击、zinst/nsis 命名 | 单信号即可判定 |
| 组合信号 | 品牌仿冒+可疑TLD、钓鱼路径+非HTTPS | 需 2+ 因子叠加 |
| 弱信号 | 可疑关键词、异常端口、长URL | 需 ≥3 个累积 |

## 威胁情报来源

- Security.X 云端威胁情报库（Cloudflare D1，35,000+ IOC）
- VirusTotal 关联文件分析
- Kaspersky OpenTIP
- 微步 ThreatBook
- 安恒 DBAPP TI
- 深信服 NDR 告警关联
- 人工逆向分析（银狐/ValleyRAT、Noah Relay 等）

## 隐私说明

- 所有 IOC 匹配在浏览器本地完成，不上传任何浏览数据
- 不收集用户信息、不追踪浏览历史
- 远程规则更新仅下载规则文件，不发送任何请求数据

## 版本历史

### v1.2.0 (2026-08-20)
- 新增白名单系统（内置可信域 + 用户自定义 + 临时放行）
- ML 引擎升级至 v5.3（多因子门控，误报/漏报压制）
- 拦截页支持"加入白名单"按钮
- 白名单优先于所有检测

### v1.0.0 (2026-08-19)
- 初始版本
- 4138 条 IOC 规则（4084 域名 + 29 IP + 15 URL + 10 文件哈希）
- 钓鱼/恶意软件/C2/下载四类拦截
- 启发式检测引擎
- 自定义规则管理
- 拦截统计与日志

## 技术栈

- Manifest V3 (Service Worker + ES Module)
- chrome.declarativeNetRequest
- chrome.downloads API
- 纯原生 JavaScript，无第三方依赖