# MythoFable Migration Progress

## 戦略
~/gemini_mythos_m を ~/MythoFable に移動し、旧パスにsymlinkを作成済み。中断しても動作継続する。各ステップ完了後 [ ] を [x] に変更。

## チェックリスト
- [x] Step1: ディレクトリ移動 + symlink作成
- [x] Step2: dashboard.py 内 BASE_DIR を新パスに変更
- [x] Step3: 各.pyファイル内のパス参照を新パスに変更
- [x] Step4: launchd 3つ全て com.mythofable.* に移行完了: launchd plist 3つを新ラベル(com.mythofable.*)・新パスで再作成
- [x] Step5: crontab 6エントリを新パスに変更
- [x] Step6: pfctl anchor gemini-mythos -> mythofable
- [x] Step7: 動作確認
- [x] Step8: symlink削除・旧plist削除・最終クリーンアップ

## 重要パス
- 新ディレクトリ: ~/MythoFable/
- 旧symlink: ~/gemini_mythos_m -> ~/MythoFable (Step8まで維持)

## ロールバック方法
rm ~/gemini_mythos_m \&\& mv ~/MythoFable ~/gemini_mythos_m


## ✅ 全Step完了 2026-06-15
MythoFableへの移行が完全に完了しました。
