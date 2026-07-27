import os

def execute_active_defense(file_path: str, old_text: str, new_text: str, attacker_ip: str) -> str:
    """
    【アクティブ・ディフェンス一括執行】
    1. 該当ファイルの脆弱なコードを安全なコードに書き換えます（パッチ適用）。
    2. 攻撃者のIPアドレスをファイアウォールに登録して即座に遮断します。
    """
    results = []
    
    # --- 1. パッチ適用フェーズ ---
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        
        if old_text in content:
            updated_content = content.replace(old_text, new_text)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(updated_content)
            results.append(f"[PATCH] Success: Patched '{file_path}'. Vulnerable code replaced.")
        else:
            results.append(f"[PATCH] Skipped/Error: 'old_text' not found in '{file_path}'. Maybe already patched?")
    else:
        results.append(f"[PATCH] Error: Target file '{file_path}' does not exist.")
        
    # --- 2. IP遮断フェーズ ---
    log_file = "blocked_ips.txt"
    
    # 既存のブラックリストを読み込んで重複チェック
    existing_ips = []
    if os.path.exists(log_file):
        with open(log_file, "r", encoding="utf-8") as f:
            existing_ips = [line.strip() for line in f.readlines()]
            
    # まだ登録されていないIPの場合のみ追記する
    if attacker_ip not in existing_ips:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"{attacker_ip}\n")
        print(f"🚨 [FIREWALL ACTION] ALERT: IP {attacker_ip} has been BLOCKED via iptables/pfctl simulator.")
        results.append(f"[FIREWALL] Success: Attacker IP {attacker_ip} has been added to the blacklist.")
    else:
        results.append(f"[FIREWALL] Skipped: Attacker IP {attacker_ip} is already in the blacklist.")

    
    return "\n".join(results)

