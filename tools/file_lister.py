from pathlib import Path

def list_project_files(dir_path: str = "./target_repo") -> str:
    """
    指定されたディレクトリ配下のファイル構成を再帰的に走査し、ファイル一覧を軽量なテキスト形式で返します。
    エージェントが全体の構造を把握し、どのファイルを読み込むべきか判断するために最初に使用します。
    
    Args:
        dir_path (str): スキャン対象のディレクトリパス。デフォルトは './target_repo'。
    """
    path = Path(dir_path)
    if not path.exists():
        return f"Error: Directory {dir_path} does not exist."
        
    lines = []
    lines.append(f"=== File List for {dir_path} ===")
    
    # 負荷とノイズを減らすため、主要なソースコード拡張子や設定ファイルを対象にする
    # 不要なキャッシュディレクトリ（.venv, __pycache__, .gitなど）は除外
    ignore_dirs = {".venv", "__pycache__", ".git", ".pytest_cache", "egg-info"}
    
    try:
        for p in path.rglob("*"):
            # 除外に対象のディレクトリが含まれているかチェック
            if any(part in ignore_dirs for part in p.parts):
                continue
                
            if p.is_file():
                # 相対パスを取得して追加
                relative_path = p.relative_to(path.parent if path.parent else path)
                lines.append(f"- {relative_path}")
                
        if len(lines) == 1:
            return f"No files found in {dir_path}."
            
        return "\n".join(lines)
    except Exception as e:
        return f"Error listing files: {str(e)}"
