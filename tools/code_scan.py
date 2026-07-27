import subprocess

def run_semgrep(path: str = ".") -> str:
    """
    指定されたパスに対してSemgrepによる静的コードスキャンを実行し、検出された脆弱性のレポートを返します。
    
    Args:
        path (str): スキャン対象のディレクトリまたはファイルパス。デフォルトはカレントディレクトリ。
    """
    cmd = ["semgrep", "--config=auto", path]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        return result.stdout if result.stdout else "Semgrep found no issues."
    except Exception as e:
        return f"Error running semgrep: {str(e)}"
