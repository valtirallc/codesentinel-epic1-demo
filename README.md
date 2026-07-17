# vulnerable-api

A deliberately vulnerable Express.js API used as a demo target for codesentinel.

This application simulates a simple items management service with authentication and admin routes. It contains multiple intentional security vulnerabilities to demonstrate what codesentinel can find.

## Running

```bash
npm install
npx ts-node src/app.ts
```

## Scan it

```bash
codesentinel scan --model claude --path ./src --fail-on high
```
