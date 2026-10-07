import nodemailer from "nodemailer";
import { config } from "../config.js";

const transporter = config.smtpHost
  ? nodemailer.createTransport({
      host: config.smtpHost,
      port: config.smtpPort,
      secure: config.smtpPort === 465,
      auth: {
        user: config.smtpUser,
        pass: config.smtpPass,
      },
    })
  : null;

export async function sendApprovalEmail(
  to: string,
  name: string,
  apiKey: string
) {
  if (!transporter) {
    console.warn("SMTP not configured — skipping email to", to);
    return;
  }

  await transporter.sendMail({
    from: `Correlic <${config.emailFrom}>`,
    to,
    subject: `You're in, ${name} — here's your Correlic API key`,
    html: `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 560px; margin: 0 auto; padding: 40px 20px; color: #1a1a2e;">
        <h1 style="font-size: 24px; margin-bottom: 8px;">Hey ${name}!</h1>
        <p style="color: #555; font-size: 15px; line-height: 1.6;">
          I just approved your Correlic access. You're one of the first people to try this — that means a lot.
        </p>
        <p style="color: #555; font-size: 15px; line-height: 1.6;">
          Here's your API key. Use it for both the agent setup and the security dashboard.
        </p>

        <div style="background: #0a0612; border-radius: 12px; padding: 20px; margin: 24px 0; border: 1px solid #2a1f3d;">
          <p style="color: #9333ea; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin: 0 0 8px 0;">Your API Key</p>
          <code style="color: #e8dff5; font-size: 14px; word-break: break-all; font-family: 'JetBrains Mono', 'Courier New', monospace;">${apiKey}</code>
        </div>

        <p style="color: #888; font-size: 13px; margin-top: 16px;">
          <strong>Save this key now</strong> — it won't be shown again. If you lose it, just reply to this email.
        </p>

        <h2 style="font-size: 18px; margin-top: 32px;">Get started in 60 seconds</h2>

        <div style="background: #f5f3ff; border-radius: 8px; padding: 16px; margin: 16px 0;">
          <p style="margin: 0 0 8px 0; font-size: 14px; font-weight: 600;">Windows (PowerShell as Admin):</p>
          <code style="font-size: 13px; color: #6b21a8;">irm https://correlic.com/install/win | iex</code>
        </div>

        <div style="background: #f5f3ff; border-radius: 8px; padding: 16px; margin: 16px 0;">
          <p style="margin: 0 0 8px 0; font-size: 14px; font-weight: 600;">Linux / Docker:</p>
          <code style="font-size: 13px; color: #6b21a8;">curl -sSL https://correlic.com/install.sh | sudo bash</code>
        </div>

        <p style="color: #555; font-size: 14px; line-height: 1.6;">
          The installer will ask for your API key. Paste the key above when prompted.
          Once installed, open <strong>http://localhost:3001</strong> to access your dashboard.
        </p>

        <hr style="border: none; border-top: 1px solid #eee; margin: 32px 0;" />

        <p style="color: #555; font-size: 14px; line-height: 1.6;">
          If anything breaks or confuses you, reply directly to this email — I read every one.
        </p>

        <p style="color: #aaa; font-size: 12px; margin-top: 24px;">
          All data stays on your device. Nothing is sent to Correlic servers except key validation.
          <br />
          <a href="https://correlic.com" style="color: #9333ea;">correlic.com</a>
        </p>
      </div>
    `,
  });
}
