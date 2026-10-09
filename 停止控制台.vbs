Option Explicit

Dim shell, fso
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

Const PORT = "8080"

' 找出正在监听 8080 端口的进程 PID
Dim tmpFile, f, line, pid
tmpFile = fso.GetSpecialFolder(2) & "\intrusion_portcheck.txt"
shell.Run "%comspec% /c netstat -ano > """ & tmpFile & """", 0, True

pid = ""
If fso.FileExists(tmpFile) Then
    Set f = fso.OpenTextFile(tmpFile, 1)
    Do Until f.AtEndOfStream
        line = f.ReadLine
        If InStr(line, ":" & PORT) > 0 And InStr(line, "LISTENING") > 0 Then
            ' netstat 每行最后一段就是 PID
            pid = Trim(Mid(line, InStrRev(line, " ") + 1))
            Exit Do
        End If
    Loop
    f.Close
    fso.DeleteFile tmpFile, True
End If

If pid <> "" Then
    shell.Run "taskkill /F /PID " & pid, 0, True
    MsgBox "服务已停止。", 64, "Intrusion 渗透测试控制台"
Else
    MsgBox "服务未在运行。", 64, "Intrusion 渗透测试控制台"
End If