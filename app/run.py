import os
import sys
import uvicorn
from pathlib import Path

if __name__ == "__main__":
    # 无论从哪个目录启动，都把 run.py 所在目录加入 sys.path，
    # 这样 uvicorn 一定能找到 main 模块（对便携 Python 尤其重要）
    app_dir = Path(__file__).resolve().parent
    os.chdir(str(app_dir))
    if str(app_dir) not in sys.path:
        sys.path.insert(0, str(app_dir))
    uvicorn.run("main:app", host="127.0.0.1", port=8080, log_level="info")