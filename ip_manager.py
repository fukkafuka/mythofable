import os

BLACKLIST_FILE = "blocked_ips.txt"
WHITELIST_FILE = "whitelist.txt"

def load_ips(file_path):
    if not os.path.exists(file_path):
        return []
    with open(file_path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f.readlines() if line.strip()]

def save_ips(file_path, ip_list):
    with open(file_path, "w", encoding="utf-8") as f:
        for ip in sorted(list(set(ip_list))):
            f.write(f"{ip}\n")

def move_ip(from_file, to_file, list_name_from, list_name_to):
    from_ips = load_ips(from_file)
    to_ips = load_ips(to_file)
    
    if not from_ips:
        print(f"\n⚠️  {list_name_from} は現在空っぽです。")
        return

    print(f"\n--- 現在の {list_name_from} 一覧 ---")
    for idx, ip in enumerate(from_ips):
        print(f"[{idx}] {ip}")
    
    try:
        choice = input(f"\n👉 {list_name_to} へ移したいIPの番号を入力してください（キャンセルはEnter）: ").strip()
        if choice == "":
            print("❌ キャンセルされました。")
            return
            
        target_idx = int(choice)
        if 0 <= target_idx < len(from_ips):
            target_ip = from_ips.pop(target_idx)
            to_ips.append(target_ip)
            
            save_ips(from_file, from_ips)
            save_ips(to_file, to_ips)
            print(f"✨ 成功: IP [{target_ip}] を {list_name_from} から削除し、{list_name_to} へ移動しました！")
        else:
            print("❌ 無効な番号です。")
    except ValueError:
        print("❌ 数字を入力してください。")

def main():
    print("====================================")
    print(" 🛡️  SecureGuard - IP アクセス管理ツール")
    print("====================================")
    mode = input("👉 モードを選択してください [B: Blacklist管理 / W: Whitelist管理]: ").strip().upper()
    
    if mode == "B":
        # Blacklistの一覧を出して、選んだものをWhitelistへ移す（Blacklistからは削除）
        move_ip(BLACKLIST_FILE, WHITELIST_FILE, "Blacklist", "Whitelist")
    elif mode == "W":
        # Whitelistの一覧を出して、選んだものをBlacklistへ移す（Whitelistからは削除）
        move_ip(WHITELIST_FILE, BLACKLIST_FILE, "Whitelist", "Blacklist")
    else:
        print("❌ 無効な入力です。'B' または 'W' を入力してください。")

if __name__ == "__main__":
    main()

