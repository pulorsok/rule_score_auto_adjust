已確定知名惡意行為，正確認惡意行為發生位置，以及 Quark 能否偵測
大小適中之樣本: 698ce6345e26bbba3e3bb6a9e78bc26f80ad85479b20c737ad6709bc36656bb1.apk

VT 回報 698ce6345e26bbba3e3bb6a9e78bc26f80ad85479b20c737ad6709bc36656bb1 沒問題

89cacc44f42639f27efe324f4937b923e2711b88b67b1fdae8bbae1210f573e7

What we got?
1. MalwareBazzar 下載下來的樣本 VT 不一定會報
2. VT 有報，VT Label 分類結果與 MalwareBazzar 不一致
3. 實際進入樣本，找不到關鍵程式碼 -> 疑似 MalwareBazzar 有分錯
-> 參考分析報告找出關鍵程式碼片段，以此程式碼片段產出偵測規則，挑出偵測規則 100% 的樣本
