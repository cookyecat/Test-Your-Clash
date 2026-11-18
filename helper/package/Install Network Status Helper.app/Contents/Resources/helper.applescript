on run
    launchHelper("netstatus://open")
end run
on open location requestedURL
    launchHelper(requestedURL)
end open location
on launchHelper(requestedURL)
    set resourceDir to POSIX path of (path to resource "launch.py")
    -- No remote code is accepted. Only the installed, fixed launcher handles URLs.
    set candidates to {"/opt/homebrew/bin/python3", "/usr/local/bin/python3", "/Library/Frameworks/Python.framework/Versions/Current/bin/python3", "/usr/bin/python3"}
    set py to ""
    repeat with candidate in candidates
        try
            do shell script (quoted form of candidate) & " -c 'import sys; assert sys.version_info >= (3,9)'"
            set py to candidate
            exit repeat
        end try
    end repeat
    if py is "" then
        display dialog "需要 Python 3.9 或更新版本。请安装 python.org 的 Python 3，再重新打开助手。不会自动下载或执行安装器。" with title "网络状态台" buttons {"好"} default button "好"
        return
    end if
    try
        do shell script (quoted form of py) & " " & (quoted form of resourceDir) & " " & (quoted form of requestedURL)
    on error errorText
        display dialog "助手未能完成连接。请检查 Python 3、本地端口和授权弹窗。" with title "网络状态台" buttons {"好"} default button "好"
    end try
end launchHelper
