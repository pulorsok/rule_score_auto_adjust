可以找到惡意行為，詳見/Users/shengfeng/codespace/research/toxicpanda/12d94320a25c1496ae3c7d326e07d4d92d34381d7b821f58ef9f4e135612c6d8/malware_analysis_report.md

一項問題：
1. 樣本非正規 Zip / APK 文件，導致 Quark、APKtool 等分析工具無法分析，參考 Jadx 前年十月的調查，暫無已知函式庫可解決此問題，但樣本可以修補回來，需 Quark 實現修補樣本的功能，始能分析。這也是 Jadx 目前的解決辦法: https://github.com/skylot/jadx/pull/2298

