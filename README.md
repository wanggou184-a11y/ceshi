# XSS Lab（本地 / Codespaces 靶场）

极简反射型 XSS，供 XRAY 等扫描器验证用。**不要公开暴露到公网。**

## 本地启动

```bash
python3 xss_lab.py
# http://127.0.0.1:8088/
```

验证：

```bash
curl -s 'http://127.0.0.1:8088/search?q=<script>alert(1)</script>'
```

## GitHub Codespaces

1. 把本仓库推到 GitHub  
2. 打开仓库 → **Code** → **Codespaces** → **Create codespace**  
3. 终端执行：

```bash
XSS_LAB_HOST=0.0.0.0 python3 xss_lab.py
```

4. 左侧 **Ports** 里确认 `8088` 为 **Private**  
5. 用 Forwarded Address 给扫描器（仅自己可见）

## 端点

| 路径 | 说明 |
|------|------|
| `/` | 首页 |
| `/search?q=` | 反射 XSS |
| `/echo?name=` | 反射 XSS |

## 安全

- 默认只监听 `127.0.0.1`  
- Codespaces 端口务必保持 Private  
- 测完即停
