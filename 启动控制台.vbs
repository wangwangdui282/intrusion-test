Option Explicit

Dim shell, fso, selfPath, silent, scriptDir, runScript, bundledPython, pythonCmd, i

' ===== 检测是否从压缩包内部直接运行 =====
' 从 zip 里直接双击 vbs，脚本路径会落在 Temp 下且包含 .zip，此时会报 800A0046
selfPath = LCase(WScript.ScriptFullName)
If InStr(selfPath, "\temp\") > 0 And InStr(selfPath, ".zip") > 0 Then
    MsgBox "检测到你是在压缩包内部直接运行的。请先把整个压缩包解压到一个文件夹，再双击「启动控制台.vbs」。", 48, "Intrusion 渗透测试控制台"
    WScript.Quit
End If
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

Const PORT = "8080"
Const URL = "http://127.0.0.1:8080"

' 是否静默模式（供程序内部测试用，双击时不会带这个参数）
silent = False
If WScript.Arguments.Count > 0 Then
    If LCase(WScript.Arguments(0)) = "/silent" Then silent = True
End If

' 脚本所在目录（即 intrusion-test 文件夹）
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)

' 如果服务已经在运行，直接打开浏览器
If IsPortListening(PORT) Then
    shell.Run "cmd /c start """" """ & URL & """", 0, False
    If Not silent Then
        MsgBox "控制台已在运行，已为你打开浏览器。" & vbCrLf & URL, 64, "Intrusion 渗透测试控制台"
    End If
    WScript.Quit
End If

' 启动服务（隐藏窗口运行 run.py）
runScript = scriptDir & "\app\run.py"
bundledPython = scriptDir & "\runtime\python\python.exe"
If fso.FileExists(bundledPython) Then
    pythonCmd = """" & bundledPython & """"
Else
    pythonCmd = "python"
End If

shell.Run pythonCmd & " """ & runScript & """", 0, False

' 等待服务就绪，最多等 10 秒
For i = 1 To 20
    WScript.Sleep 500
    If IsPortListening(PORT) Then Exit For
Next

' 打开浏览器
shell.Run "cmd /c start """" """ & URL & """", 0, False

If IsPortListening(PORT) Then
    If Not silent Then
        MsgBox "控制台已启动。" & vbCrLf & vbCrLf & URL & vbCrLf & vbCrLf & "要停止服务，请双击「停止控制台.vbs」。", 64, "Intrusion 渗透测试控制台"
    End If
Else
    If Not silent Then
        MsgBox "启动失败。请确认电脑已安装 Python，并在命令行里能运行 python 命令。" & vbCrLf & vbCrLf & "也可以手动进入 app 目录，运行：python run.py", 16, "Intrusion 渗透测试控制台"
    End If
End If

' 检查 8080 端口是否正在监听
Function IsPortListening(port)
    Dim tmpFile, f, line
    tmpFile = fso.GetSpecialFolder(2) & "\intrusion_portcheck.txt"
    shell.Run "%comspec% /c netstat -ano > """ & tmpFile & """", 0, True
    IsPortListening = False
    If Not fso.FileExists(tmpFile) Then Exit Function
    Set f = fso.OpenTextFile(tmpFile, 1)
    Do Until f.AtEndOfStream
        line = f.ReadLine
        If InStr(line, ":" & port) > 0 And InStr(line, "LISTENING") > 0 Then
            IsPortListening = True
            Exit Do
        End If
    Loop
    f.Close
    fso.DeleteFile tmpFile, True
End Function