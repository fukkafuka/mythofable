from pathlib import Path

def read_specific_file(file_path: str) -> str:
    """
    指定されたファイルのコード内容を読み込んで返します。
    
    Args:
        file_path (str): 読み込みたいファイルの相対パス（例: 'target_repo/app.py'）
    """
    path = Path(file_path)
    if not path.exists():
        return f"Error: File {file_path} does not exist."
    if not path.is_file():
        return f"Error: {file_path} is not a file."
        
    try:
        content = path.read_text(errors="ignore")
        return f"--- Content of {file_path} ---\n{content[:5000]}"
    except Exception as e:
        return f"Error reading file {file_path}: {str(e)}"
