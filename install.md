# 1. code agent 설치 과정
## 1.1 Node.js 설치

### **windows**: 
- [Node.js 다운로드(https://nodejs.org/ko/download)](https://nodejs.org/ko/download)
- node -v
- npm -v
### **Linux**: 
- curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
- sudo apt-get install -y nodejs
- node --version
- npm --version

## 1.2 Git 설치
- [Git 다운로드(https://git-scm.com/downloads/win)](https://git-scm.com/downloads/win)
- git -v

## 1.2 LLM 설치
### Gemini CLI
- npm install -g @google/gemini-cli
- gemini
- 보안문제 있을 경우:
  - 관리자권한으로 Windows Powershell 실행
  - Set-ExecutionPolicy RemoteSigned

### Claude code
- npm install -g @anthropic-ai/claude-code
- claude

### Codex CLI
- npm install -g @openai/codex
- codex

## 1.3 Playwright MCP 설치
- [https://github.com/microsoft/playwright-mcp](https://github.com/microsoft/playwright-mcp)
- npx @playwright/mcp@latest --help
```
{
  "mcpServers": {
    "playwright": {
      "command": "npx",
      "args": [
        "@playwright/mcp@latest"
      ]
    }
  }
}
```

### Gemini CLI:
- .gemini/settings.json
### Claude code:
- .claude.json
- claude mcp add playwright npx @playwright/mcp@latest
### claude desktop
- %user%AppData/Roaming/claude/claude_desktop_config.json
### Codex code: 잘안됨 --> wsl 을 설치하고 실행후 codex를 설치하면 된다고 함.
- .codex/config.toml
```
[mcp_servers.playwright]
command = "npx"
args = ["@playwright/mcp@latest"]
```
