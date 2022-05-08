Set-Culture bg-BG
Set-WinCultureFromLanguageListOptOut 0
Set-WinSystemLocale bg-BG
Set-WinUserLanguageList en-US -Force
Set-WinDefaultInputMethodOverride -InputTip "0409:00000409"
$LangList = Get-WinUserLanguageList
$MarkedLang = $LangList | where LanguageTag -ne "en-US"
$LangList.Remove($MarkedLang)
$LangList.Add("bg-BG")
$LangList[0].InputMethodTips.Clear()
$LangList[0].InputMethodTips.Add("0409:00000409")
$LangList[1].InputMethodTips.Clear()
$LangList[1].InputMethodTips.Add("0402:00040402")
$LangList[1].InputMethodTips.Add("0402:00030402")
Set-WinUserLanguageList $LangList -Force