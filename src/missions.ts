import type { Level } from "./labs/types";

export interface MissionRequirement {
  labId: string;
  level: Level;
  lootId?: string;
}

export interface MissionStep {
  id: string;
  number: number;
  title: string;
  briefing: string;
  objective: string;
  requirement: MissionRequirement;
  artifact: { label: string; description: string };
}

export const HARBOR_MISSION: MissionStep[] = [
  {
    id: "initial-access",
    number: 1,
    title: "顧客DBへの初期侵入",
    briefing: "Harbor Storeの検索APIに、通常のログイン画面にはないrole条件が残っています。",
    objective: "SQLインジェクション Lv4でユーザー表を読み出す",
    requirement: { labId: "sqli", level: 4 },
    artifact: { label: "管理者の認証情報", description: "DBから得た情報を、次の認証境界の調査に使います。" },
  },
  {
    id: "mfa-bypass",
    number: 2,
    title: "管理者セッションの奪取",
    briefing: "認証情報だけではMFAで止まります。デバッグ用メール配信の痕跡を調べます。",
    objective: "認証・セッション管理 Lv4でMFAコードを発見し、adminセッションを得る",
    requirement: { labId: "auth", level: 4, lootId: "auth-mfa" },
    artifact: { label: "adminセッション", description: "管理APIが発行するトークンの検証方式を調査できます。" },
  },
  {
    id: "token-forgery",
    number: 3,
    title: "サービス間トークンの偽造",
    briefing: "管理APIはJWTヘッダー内の鍵取得先を信頼しています。",
    objective: "JWT Lv4で攻撃者管理のJWKSを使い、adminトークンを偽造する",
    requirement: { labId: "jwt", level: 4, lootId: "jwt-oct" },
    artifact: { label: "内部API用admin JWT", description: "内部のURL取得機能を管理者権限で操作できます。" },
  },
  {
    id: "cloud-credential",
    number: 4,
    title: "内部メタデータへの到達",
    briefing: "画像取得サービスはリダイレクト後の接続先を再検証していません。",
    objective: "SSRF Lv4で内部メタデータのaccess-keyを取得する",
    requirement: { labId: "ssrf", level: 4, lootId: "ssrf-access-key" },
    artifact: { label: "クラウドaccess-key", description: "本番環境に残された管理用ファイルを読む足掛かりです。" },
  },
  {
    id: "production-secret",
    number: 5,
    title: "本番設定からの秘密取得",
    briefing: "本番Webルートに開発用ファイルと管理エンドポイントが残っています。",
    objective: "設定ミス Lv4で公開された秘密を回収する",
    requirement: { labId: "misconf", level: 4, lootId: "misconf-flag" },
    artifact: { label: "本番環境の秘密", description: "侵害は成立しました。最後に監査記録の信頼性を確認します。" },
  },
  {
    id: "cover-tracks",
    number: 6,
    title: "監査記録の偽装",
    briefing: "攻撃者は最後に監査ログの構造を壊し、操作主体をadminに見せかけようとします。",
    objective: "ログの穴 Lv4で監視が誤認する記録を作る",
    requirement: { labId: "logging", level: 4, lootId: "logging-flag" },
    artifact: { label: "侵害経路レポート", description: "入口から痕跡偽装までの攻撃チェーンを再構成しました。" },
  },
];

