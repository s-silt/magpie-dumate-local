# magpie-dumate-local 威胁模型

## 范围与证据

- 适用范围：`s-silt/magpie-dumate-local` 全仓库。
- 代码阅读基线：`fd6da3a4f5dd4a7d1a08b66c1cbf50b542ac9f4a`。代码、部署或信任边界变化时应复核本模型。
- 本文区分仓库明确声明、代码观察和待确认假设，供后续安全扫描和人工复核使用。
- 仓库 README.md“安装与登录”明确规定：使用自己的百度账号；Cookie 保存在本机 plugin-auth.json；不要分享 Cookie；调用消耗账号积分，积分查询只读。
- 用户确认：单人 VPS 部署；优先保护百度 Cookie 与百度云账号、账号积分与服务可用性、聊天内容与上传数据；暂不排除任何攻击者或风险；没有相关基础设施仓库，继续当前仓库。代码推断本身不构成调整发现级别的依据。

## 系统与组件

| 稳定组件名 | 覆盖代码 | 职责及边界 |
| --- | --- | --- |
| Host Integration | index.mjs：MODELS、config、auth.loader 与模块导出；package.json | 注册 Magpie/OpenCode provider；从宿主 getAuth 接收凭据并提供自定义 fetch。宿主进程、SDK、配置及凭据文件实现不在本仓库。 |
| Session Authentication | index.mjs：parseCookie、cookieOf、login、auth.methods | 遮盖输入 Cookie，校验语法，验证账号身份，返回 refresh Cookie 供宿主持久化；跨越用户输入和宿主存储边界。 |
| Console Access | index.mjs：consoleGet、gatewayToken、tokenDeadline、usage | 向百度控制台获取用户身份、网关 token 和积分；持有进程内 token 缓存并按 Cookie 哈希区分账号。 |
| Chat Relay | index.mjs：chat、normalizeReasoning、relay | 向固定百度网关发起聊天请求并流式转发响应；跨越本地宿主与远程模型服务边界。 |

tests/index.test.mjs 是以上组件的模拟测试证据，不是单独部署组件；测试存在不等于所有安全性质已实测验证。

## 数据流与信任边界

1. 用户在百度网页登录后，将控制台 Cookie 手动粘贴给宿主插件输入框。
2. Session Authentication 经 Console Access 只向 https://console.bce.baidu.com/api/dumate/user/info 验证身份；宿主负责将 Cookie 作为 refresh 写入本机 plugin-auth.json。
3. 宿主从 getAuth 提供会话；Console Access 向同源 /api/dumate/app/token/get 换取短期 token，在内存缓存。
4. Chat Relay 只允许 POST https://dumate-svc.baidu.com/gateway/apis/v1/chat/completions，用 Bearer token 发送提示词、消息、工具描述及可能的图像内容；正常响应体直接流式交回宿主。
5. 积分查询向控制台固定 quota_overview 路径 GET；模型调用会消耗账号积分。
6. 仓库未实现监听端口、远程登录入口、独立服务端或租户隔离层。是否经 VPS、代理或远程 Magpie 暴露，由实际部署决定。

## 入口与可达性

- 宿主登录提示与 authorize/callback：Cookie 输入及取消信号。
- 宿主 config、loader/getAuth 与自定义 fetch：URL、方法、请求体及 AbortSignal；调用者权限由宿主决定。
- 宿主 usage：账号凭据和积分展示。
- 百度控制台及网关返回的状态码、重定向、JSON、HTTP 头、响应体和 SSE。
- 安装/更新插件及宿主的依赖供应链；仓库 package.json 没有直接依赖声明，SDK 由宿主集成。
- 本机凭据存储、代理、TLS 信任与网络出口的控制者属于外部信任边界，不能仅因未在本仓库实现而认定风险已被接受。

## 资产与影响

- 高敏感凭据：百度控制台 Cookie，可能具有超出本插件功能的百度云账号权限；实际权限未知。
- 短期网关 token、账号 ID 和积分余额/消耗，以及账号可用性。
- 提示词、聊天记录、工具信息、图像内容和模型输出，可能含敏感数据；用户已明确将聊天内容与上传数据列为优先保护资产。
- 本机/服务器上的宿主完整性与会话可用性。
- 用户将凭据/账号、积分/可用性、聊天/上传数据均列为优先保护资产，但没有指定一类高于其他类别。不得仅因资产在此列表中就自动上调，仍须扫描确认可达路径，且难利用或未经验证的发现不提高优先级。

## 攻击者与用户确认的环境

威胁范围保留：能影响聊天内容或插件调用输入的主体、返回异常数据的远端服务、网络/代理控制者、能访问宿主凭据的本机主体及被污染的插件/宿主供应链。用户明确暂不排除任何攻击者或风险，包括本机高权限主体；不得因“个人使用”或“需要本机权限”自行降级。具体权限仍以扫描发现中的前提为准。

用户确认部署于单人 VPS。是否有远程 Web/API 入口、反向代理、宿主监听地址、VPS 管理方式和出口拓扑尚未知；不能从“单人”推断无网络入口或自动接受网络风险。README 的美国/香港 VPS 连通性说明不是实际拓扑证明。

恶意模型内容只有经宿主执行工具或渲染内容才可能越过更多边界；本仓库未实现工具执行器，不能臆测已有执行链。

## 已观察的控制与局限

- Cookie 校验禁止换行、非允许字符、超长输入及重复/空 bce-sessionid；错误不回显输入。
- 控制台目标和聊天目标为固定 HTTPS 地址；redirect: manual；聊天要求 URL 完全匹配且 POST。
- 聊天重新构建请求头，只发网关 Bearer token，不把调用方 Cookie/Authorization 透传。
- 控制台请求有 20 秒超时；MAX_CONSOLE_BODY 检查在 res.text() 读完后进行，不能把它描述成流读取硬上限。
- token 按 Cookie SHA-256 分区，缓存最多 8 项、限制存活时间；并发刷新合并，网关 401 最多刷新重试一次。
- 错误使用固定消息；响应头只转发 content-type/cache-control/retry-after；成功响应体保留上游内容。
- 仓库测试覆盖凭据分流、重定向拒绝、账号缓存分离、错误脱敏、取消、重试和流式行为；本模型基于测试代码阅读，不代表真实宿主与部署验收。
- 宿主文件权限/加密、远程访问认证、代理安全、TLS 环境、登出后的宿主实例生命周期及真实部署未在本仓库验证。

## 范围外与已接受风险

用户明确表示暂不排除任何攻击者或风险，没有已接受风险。Magpie/OpenCode 宿主、百度服务端及外部基础设施的源码未包含在本次扫描中；这是证据限制，不表示接受相关风险。

仓库无 Terraform、Kubernetes、Helm、Pulumi、CloudFormation、Docker 或其他部署配置；可访问仓库清单未发现明确关联的基础设施仓库。用户确认没有相关基础设施仓库并要求继续当前仓库；因此未使用基础设施仓库，部署控制仍为证据缺口。

## 发现标签

- Component：Host Integration、Session Authentication、Console Access、Chat Relay，按根因所在组件归属。
- CVE：存在准确且适用的公开 CVE 编号时填写，不臆造。
- Affected Asset：百度 Cookie/百度云账号、网关令牌、账号积分、服务可用性、聊天内容/上传数据或宿主完整性，按实际影响填写。

## 仍待确认的证据缺口

- VPS 的远程入口、监听地址、认证、代理、TLS 信任与主机加固措施；没有将其缺失视作已知漏洞或已接受风险。
- Cookie 的实际账号权限、聊天数据具体分级及宿主凭据文件权限/加密；优先保护方向已确认。

## 复核规则

从扫描器严重性出发，保留其对利用前提、难度与影响的判断。用户没有排除任何风险，预计多数发现维持原级别；只有用户提供的边界事实可支持调整。每次记录同时解释利用前提和所及资产，且仅在扫描确认路径通向用户重点资产、利用不困难且已验证时谨慎考虑提高。
